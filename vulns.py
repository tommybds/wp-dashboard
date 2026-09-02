#!/usr/bin/env python3
"""Veille de vulnérabilités du parc — croisement local, source ouverte.

Données : WPVulnerability (https://www.wpvulnerability.net/), API ouverte, sans
clé ni compte, qui agrège plusieurs sources publiques (CVE.org, Patchstack,
Wordfence, WPScan) et indexe par *slug* d'extension — exactement ce que produit
notre inventaire. Aucune information sur le parc n'est transmise : on demande
« quelles failles connaît-on pour l'extension X ? », jamais « voici mes sites ».

Le résultat de chaque slug est mis en cache 24 h dans data/vuln_feed.json ; seuls
les slugs réellement présents dans l'inventaire sont interrogés, avec une pause
entre les appels (l'API est offerte gracieusement : on l'utilise sobrement).

Usage :
    python3 vulns.py --fetch           # rafraîchit le cache (1×/jour, via cron)
    python3 vulns.py --scan            # croise → data/vulns_found.json
    python3 vulns.py --fetch --scan --print
"""
import os, sys, json, re, time, datetime, html
import urllib.request, urllib.error

# Briques communes à tous les scripts du dépôt (cf. dashlib.py). `site_visible`
# EST la règle d'affichage de l'interface : la veille ne doit signaler que des
# sites réellement suivis.
from dashlib import BASE, DATA_DIR as DATA, load_json, site_visible
from dashlib import save_json as _save_json

FEED_PATH = os.path.join(DATA, "vuln_feed.json")
FOUND_PATH = os.path.join(DATA, "vulns_found.json")
FLEET_PATH = os.path.join(DATA, "fleet.json")

API = "https://www.wpvulnerability.net"
USER_AGENT = "WPDashboard-VulnWatch/1.0 (+https://github.com/tommybds/wp-dashboard)"
TTL = 24 * 3600          # durée de vie d'une entrée en cache
PAUSE = 0.15             # pause entre deux appels (usage sobre de l'API)
TIMEOUT = 25

# Une entrée d'inventaire qui n'est pas une vraie extension du dépôt officiel
# (drop-ins WordPress) : inutile de l'interroger. Les mu-plugins propres à une
# installation s'ajoutent par la clé `vuln_skip_slugs` de config.json — ils
# n'ont rien à faire en dur dans un projet générique.
SKIP_SLUGS = {"advanced-cache.php", "maintenance.php", "object-cache.php",
              "db.php", "wp-cache-config.php"}
try:
    from dashboard_config import CONFIG as _CONFIG
except Exception:  # configuration absente : on garde les défauts
    _CONFIG = {}
_EXTRA_SKIP = _CONFIG.get("vuln_skip_slugs") or []
if isinstance(_EXTRA_SKIP, (list, tuple, set)):
    SKIP_SLUGS |= {str(x).strip() for x in _EXTRA_SKIP if str(x).strip()}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}


# ---------------------------------------------------------------------------
#  Comparaison de versions à la PHP (version_compare)
#  Indispensable : un découpage numérique naïf classerait « 1.0-beta » APRÈS
#  « 1.0 » et raterait donc des intervalles de vulnérabilité.
# ---------------------------------------------------------------------------
# Ordre documenté par PHP :
#   toute autre chaîne < dev < alpha = a < beta = b < RC = rc < # < pl = p
# où « # » désigne un NOMBRE (php_version_compare compare une partie numérique
# sous la forme interne « #N# »). Les chiffres se rangent donc SOUS pl/p, et
# au-dessus de rc — c'est bien ce que fait _rank ci-dessous.
#
# La valeur « # » du dictionnaire, elle, sert à autre chose : c'est le
# rembourrage d'une partie ABSENTE (« 1.0 » comparé à « 1.0.0 »). PHP traite ce
# cas hors boucle : si la version la plus longue continue par un nombre, elle
# est la plus grande. D'où un rang STRICTEMENT inférieur à celui des chiffres,
# et supérieur à rc (« 1.0-RC2 » < « 1.0 »).
_SPECIAL = {"dev": -6, "alpha": -5, "a": -5, "beta": -4, "b": -4,
            "rc": -3, "#": -2, "pl": 1, "p": 1}
_NUM_RE = re.compile(r"^[0-9]+$")


def _is_num(part):
    """Partie purement numérique ASCII.

    `str.isdigit()` accepte les chiffres Unicode (« ² », « ٣ ») que `int()`
    refuse ensuite : une version exotique faisait alors remonter une ValueError
    au milieu du croisement.
    """
    return bool(_NUM_RE.match(part))


def _canonicalize(v):
    v = re.sub(r"[-_+]", ".", str(v or ""))
    v = re.sub(r"([^.\d])(\d)", r"\1.\2", v)
    v = re.sub(r"(\d)([^.\d])", r"\1.\2", v)
    return [p for p in v.split(".") if p]


def _rank(part):
    # chaîne inconnue : -7, soit sous « dev », comme PHP (found = -1).
    return 0 if _is_num(part) else _SPECIAL.get(part.lower(), -7)


def version_compare(a, b):
    """-1 si a < b, 0 si égal, 1 si a > b (sémantique PHP version_compare)."""
    pa, pb = _canonicalize(a), _canonicalize(b)
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else "#"
        y = pb[i] if i < len(pb) else "#"
        if _is_num(x) and _is_num(y):
            if int(x) != int(y):
                return -1 if int(x) < int(y) else 1
        else:
            rx, ry = _rank(x), _rank(y)
            if rx != ry:
                return -1 if rx < ry else 1
    return 0


def _cmp_ok(version, operator, bound):
    """Applique un opérateur WPVulnerability (lt, le, gt, ge, eq, ne)."""
    if not bound:
        return True
    c = version_compare(version, bound)
    op = (operator or "").lower()
    if op == "lt":
        return c < 0
    if op == "le":
        return c <= 0
    if op == "gt":
        return c > 0
    if op == "ge":
        return c >= 0
    if op == "eq":
        return c == 0
    if op == "ne":
        return c != 0
    # opérateur absent ou inconnu : borne non contraignante (on ne devine pas)
    return True


def affects(operator, version):
    """La version est-elle dans l'intervalle décrit par `operator` ?

    Choix CONSERVATEUR, volontaire : quand `operator` est nul ou illisible, on
    renvoie True — l'enregistrement est retenu. Faute d'intervalle, on préfère
    un signalement à vérifier à la main plutôt que masquer une faille réelle
    (cas du cœur, où l'API a déjà filtré par version). `_cmp_ok` applique la
    même règle borne par borne quand l'opérateur manque.
    """
    if not isinstance(operator, dict):
        return True
    if not version:
        return False
    return (_cmp_ok(version, operator.get("min_operator"), operator.get("min_version"))
            and _cmp_ok(version, operator.get("max_operator"), operator.get("max_version")))


# ---------------------------------------------------------------------------
#  Cache et appels API
# ---------------------------------------------------------------------------
def save_json(path, obj, mode=0o600):
    """Écriture atomique en 0600 : ces fichiers nomment les sites du parc et
    leurs failles connues — pas de lecture par un autre compte de la machine.

    JSON compact (`indent=None`) : le cache de vulnérabilités pèse plusieurs Mo,
    l'indenter le doublerait pour rien."""
    _save_json(path, obj, mode=mode, indent=None, fsync=True)


def api_get(path):
    """→ (data, erreur). Un 404 signifie « extension inconnue », pas une panne."""
    req = urllib.request.Request(API + path, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as e:
        return (None, "inconnu") if e.code == 404 else (None, f"HTTP {e.code}")
    except Exception as e:
        return None, f"{type(e).__name__}"
    if not isinstance(body, dict) or body.get("error"):
        return None, str(body.get("message") or "réponse en erreur")[:120]
    return body.get("data"), None


def clean(s):
    """Les libellés de l'API contiennent des entités HTML (&#8211;)."""
    return html.unescape(str(s or "")).strip()


def extract_vulns(data):
    """Normalise la liste de vulnérabilités d'une réponse."""
    out = []
    for v in (data or {}).get("vulnerability") or []:
        if not isinstance(v, dict):
            continue
        sources = [s for s in (v.get("source") or []) if isinstance(s, dict)]
        cve = next((s.get("id") for s in sources
                    if str(s.get("id", "")).upper().startswith("CVE-")), None)
        link = next((s.get("link") for s in sources if s.get("link")), None)
        desc = next((s.get("description") for s in sources if s.get("description")), None)
        # CVSS : `cvss3` porte les libellés complets (« high »), `cvss` les
        # abrège (« h ») — on préfère donc cvss3 et on garde cvss en repli.
        # Environ 40 % des enregistrements n'ont aucun CVSS : gravité inconnue.
        impact = v.get("impact") if isinstance(v.get("impact"), dict) else {}
        cvss = {}
        for key in ("cvss3", "cvss4", "cvss"):
            c = impact.get(key)
            if isinstance(c, dict) and (c.get("severity") or c.get("score")):
                cvss = c
                break
        out.append({
            "uuid": v.get("uuid"),
            "name": clean(v.get("name")),
            "description": clean(desc or v.get("description"))[:400],
            "cve": cve,
            "link": link,
            "severity": str(cvss.get("severity") or "").lower(),
            "score": cvss.get("score"),
            "operator": v.get("operator"),
            "unfixed": str((v.get("operator") or {}).get("unfixed") or "0") in ("1", "true"),
        })
    return out


def refresh(kind, key, cache, stats, force=False):
    """Met en cache `kind/key` si l'entrée est absente ou périmée."""
    bucket = cache.setdefault(kind, {})
    entry = bucket.get(key)
    now = time.time()
    if not force and entry and (now - entry.get("fetched", 0)) < TTL:
        stats["cache"] += 1
        return
    path = {"plugin": f"/plugin/{key}/", "core": f"/core/{key}/",
            "php": f"/php/{key}/"}[kind]
    data, err = api_get(path)
    time.sleep(PAUSE)
    if err == "inconnu":
        bucket[key] = {"fetched": now, "vulns": [], "unknown": True}
        stats["unknown"] += 1
        return
    if err:
        stats["errors"] += 1
        stats["error_detail"].setdefault(err, 0)
        stats["error_detail"][err] += 1
        return  # on conserve l'ancienne entrée plutôt que de l'effacer
    bucket[key] = {"fetched": now, "vulns": extract_vulns(data),
                   "name": clean((data or {}).get("name"))}
    stats["fetched"] += 1


def fleet_targets(fleet):
    """Slugs d'extensions, versions de cœur et de PHP réellement présents."""
    retenus = {}
    for srv in fleet.get("servers", []):
        for s in srv.get("sites", []):
            if not site_visible(s):
                continue
            k = s.get("kuma") or s.get("domain")
            if not k or (k in retenus and not s.get("kuma")):
                continue
            s = dict(s, srv=srv.get("name"))
            retenus[k] = s
    slugs, cores, phps = set(), set(), set()
    for s in retenus.values():
        if s.get("core_version"):
            cores.add(str(s["core_version"]))
        if s.get("php_version"):
            phps.add(str(s["php_version"]))
        for p in (s.get("plugins_list") or []):
            n = p.get("name")
            if n and n not in SKIP_SLUGS and not str(n).endswith(".php"):
                slugs.add(n)
    return retenus, slugs, cores, phps


def do_fetch(force=False, verbose=True):
    fleet = load_json(FLEET_PATH, {"servers": []})
    _, slugs, cores, phps = fleet_targets(fleet)
    cache = load_json(FEED_PATH, {})
    stats = {"fetched": 0, "cache": 0, "unknown": 0, "errors": 0, "error_detail": {}}
    total = len(slugs) + len(cores) + len(phps)
    done = 0
    for kind, keys in (("plugin", sorted(slugs)), ("core", sorted(cores)), ("php", sorted(phps))):
        for k in keys:
            refresh(kind, k, cache, stats, force)
            done += 1
            if verbose and done % 50 == 0:
                print(f"  … {done}/{total}", flush=True)
    cache["_updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    save_json(FEED_PATH, cache)
    msg = (f"{stats['fetched']} interrogés, {stats['cache']} déjà en cache, "
           f"{stats['unknown']} inconnus de la base, {stats['errors']} erreurs")
    if stats["error_detail"]:
        msg += " (" + ", ".join(f"{k}×{v}" for k, v in stats["error_detail"].items()) + ")"
    # Statut d'échec au-delà de 20 % d'appels ratés : le cache reste alors
    # largement périmé et le croisement qui suit sous-estime le risque. Les
    # entrées servies par le cache ne comptent pas (aucun appel n'a eu lieu).
    tentes = stats["fetched"] + stats["errors"] + stats["unknown"]
    trop = bool(tentes) and stats["errors"] * 5 > tentes
    if trop:
        msg += f" — plus de 20 % d'échecs ({stats['errors']}/{tentes}), base incomplète"
    return not trop, msg


# ---------------------------------------------------------------------------
#  Croisement local
# ---------------------------------------------------------------------------
#  L'API note la gravité tantôt en toutes lettres (« high »), tantôt abrégée
#  (« h ») selon le bloc CVSS retenu : les deux formes sont acceptées.
SEV_ALIAS = {"c": "critical", "h": "high", "m": "medium", "l": "low", "n": "",
             "critical": "critical", "high": "high", "medium": "medium",
             "low": "low", "none": ""}


def sev_of(v):
    s = SEV_ALIAS.get(str(v.get("severity") or "").strip().lower())
    if s:
        return s
    try:
        sc = float(v.get("score"))
    except (TypeError, ValueError):
        return ""
    if sc <= 0:
        return ""
    return "critical" if sc >= 9 else "high" if sc >= 7 else "medium" if sc >= 4 else "low"


def do_scan():
    fleet = load_json(FLEET_PATH, {"servers": []})
    cache = load_json(FEED_PATH, {})
    retenus, _, _, _ = fleet_targets(fleet)
    plugins, cores, phps = cache.get("plugin", {}), cache.get("core", {}), cache.get("php", {})

    def hits(entry, version, kind, component, extra=None):
        out = []
        for v in (entry or {}).get("vulns", []):
            if not affects(v.get("operator"), version):
                continue
            item = {"kind": kind, "component": component, "version": version,
                    "title": v["name"], "cve": v.get("cve"), "link": v.get("link"),
                    "description": v.get("description"), "severity": sev_of(v),
                    "score": v.get("score"), "unfixed": v.get("unfixed"),
                    "uuid": v.get("uuid")}
            if extra:
                item.update(extra)
            out.append(item)
        return out

    # PHP à part : une faille PHP n'est pas corrigeable site par site (c'est
    # l'hébergement qui met à jour), elle se répète à l'identique sur tous les
    # sites d'un même serveur, et surtout Debian/Plesk RÉTROPORTENT les
    # correctifs sans changer le numéro de version — la comparer par version
    # produit donc des faux positifs. On la regroupe par version, à titre
    # indicatif, au lieu de la mêler aux extensions qui, elles, sont actionnables.
    php_versions = {}
    for cle, s in retenus.items():
        pv = s.get("php_version")
        if not pv:
            continue
        entry = php_versions.setdefault(str(pv), {"version": str(pv), "sites": [], "findings": []})
        entry["sites"].append(cle)
    for pv, entry in php_versions.items():
        f = hits(phps.get(pv), pv, "php", "PHP")
        f.sort(key=lambda v: (-SEVERITY_ORDER.get(v["severity"], 0), v["title"]))
        entry["findings"] = f
        entry["count"] = len(f)
        entry["worst"] = f[0]["severity"] if f else ""
        entry["sites"].sort()
    php_list = sorted([e for e in php_versions.values() if e["count"]],
                      key=lambda e: (-SEVERITY_ORDER.get(e["worst"], 0), e["version"]))

    sites, totals = [], {"critical": 0, "high": 0, "medium": 0, "low": 0, "": 0}
    for cle, s in retenus.items():
        found = []
        core = s.get("core_version")
        if core:
            # `update_to` renseigne aussi pour le cœur : sans lui, l'interface
            # affichait « aucun correctif » alors qu'une mise à jour existe.
            found += hits(cores.get(str(core)), core, "core", "WordPress",
                          {"update_to": s.get("core_update") or ""})
        for p in (s.get("plugins_list") or []):
            slug, ver = p.get("name"), p.get("version")
            if not slug or not ver or slug in SKIP_SLUGS:
                continue
            found += hits(plugins.get(slug), ver, "plugin", slug,
                          {"status": p.get("status"), "update_to": p.get("to") or ""})
        if not found:
            continue
        found.sort(key=lambda v: (-SEVERITY_ORDER.get(v["severity"], 0),
                                  v["kind"] != "core", v["component"]))
        for v in found:
            totals[v["severity"]] = totals.get(v["severity"], 0) + 1
        sites.append({"domain": cle, "server": s.get("srv") or "", "via": s.get("via"),
                      "count": len(found), "worst": found[0]["severity"], "findings": found})

    sites.sort(key=lambda x: (-SEVERITY_ORDER.get(x["worst"], 0), -x["count"], x["domain"]))
    res = {"generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
           "feed_updated": cache.get("_updated"),
           "known_plugins": len(plugins), "sites_scanned": len(retenus),
           "sites_affected": len(sites), "totals": totals, "sites": sites,
           "php": php_list}
    save_json(FOUND_PATH, res)
    return res


def main():
    args = sys.argv[1:]
    fetch_ok = True
    if "--fetch" in args:
        print("Rafraîchissement de la base de vulnérabilités…", flush=True)
        fetch_ok, msg = do_fetch(force="--force" in args)
        print(("OK — " if fetch_ok else "ÉCHEC — ") + msg)
    if "--scan" in args or "--fetch" not in args:
        r = do_scan()
        t = r["totals"]
        print(f"{r['sites_affected']}/{r['sites_scanned']} sites touchés — "
              f"{t.get('critical',0)} critiques, {t.get('high',0)} élevées, "
              f"{t.get('medium',0)} moyennes, {t.get('low',0)} faibles")
        if "--print" in args:
            for s in r["sites"][:30]:
                print(f"\n  {s['domain']} ({s['count']})")
                for v in s["findings"][:6]:
                    fix = f" → MAJ {v['update_to']}" if v.get("update_to") else (
                        " ⚠ non corrigée" if v.get("unfixed") else "")
                    print(f"    [{v['severity'] or '?':8}] {v['component']} {v['version']}"
                          f"{fix}  {(v.get('cve') or '')}")
    if not fetch_ok:
        sys.exit(1)   # visible dans le journal cron : la base n'est pas à jour


if __name__ == "__main__":
    main()
