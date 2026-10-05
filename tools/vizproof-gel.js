/* Gel des carrousels et animations pour une capture reproductible (dashboard Sumotori).
   Le carrousel reste VISIBLE et contrôlé, sur sa première diapositive : un carrousel
   cassé (JS absent, images manquantes, mise en page éclatée) se voit dans l'écart. */
(function () {
  var $ = window.jQuery;
  function sur(f) { try { f(); } catch (e) {} }
  if ($) {
    sur(function () { $('.slick-initialized').each(function () { var s = $(this);
      sur(function () { s.slick('slickPause'); });
      // Capture tombée en pleine transition : VizProof coupe les transitions CSS,
      // la fin d'animation n'arrive jamais et Slick ignorerait le retour à 0.
      sur(function () { var o = s.slick('getSlick'); o.options.autoplay = false; o.options.waitForAnimate = false; o.animating = false; });
      sur(function () { s.slick('slickGoTo', 0, true); }); }); });
    sur(function () { $('.owl-carousel').each(function () { var o = $(this);
      o.trigger('stop.owl.autoplay'); o.trigger('to.owl.carousel', [0, 0, true]); }); });
  }
  document.querySelectorAll('.swiper, .swiper-container, .swiper-initialized').forEach(function (el) {
    var s = el.swiper; if (!s) return;
    sur(function () { s.autoplay && s.autoplay.stop(); });
    sur(function () { s.params.loop && s.slideToLoop ? s.slideToLoop(0, 0, false) : s.slideTo(0, 0, false); });
  });
  document.querySelectorAll('.splide').forEach(function (el) {
    var s = el.splide; if (!s) return;
    sur(function () { s.Components.Autoplay && s.Components.Autoplay.pause(); }); sur(function () { s.go(0); });
  });
  if (window.Flickity) document.querySelectorAll('.flickity-enabled').forEach(function (el) {
    var f = window.Flickity.data(el); if (!f) return;
    sur(function () { f.stopPlayer && f.stopPlayer(); }); sur(function () { f.select(0, false, true); });
  });
  // Animations SVG (SMIL) : hors de portée du gel CSS de VizProof.
  document.querySelectorAll('svg').forEach(function (s) { sur(function () { s.pauseAnimations(); s.setCurrentTime(0); }); });
  // Minuteries de défilement maison : plus rien ne bouge jusqu'à la capture.
  sur(function () { var id = setInterval(function () {}, 1e6); for (var i = 1; i <= id; i++) clearInterval(i); });
})();
