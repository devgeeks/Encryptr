(function (window, Encryptr, undefined) {
  "use strict";
  var console = window.console || {};
  console.log = console.log || function(){};
  var Backbone    = window.Backbone,
      _           = window._,
      $           = window.$;


    Encryptr.prototype.PopFadeEffect = window.BackStack.Effect.extend({

        fromViewTransitionProps:{duration:0.3, easing:'ease-in-out', delay:0.1},

        toViewTransitionProps:{duration:0.3, easing:'ease-in-out', delay:0.1},

        play:function ($fromView, $toView, callback, context) {

            var that = this,
                timeout,
                activeTransitions = 0,
                transitionProp = that.vendorPrefix === '' ? 'transition'
                    : ['-' + that.vendorPrefix.toLowerCase(), '-', 'transition'].join('');

            var transitionEndHandler = function (event) {
                if (activeTransitions >= 0) {
                    activeTransitions--;

                    $(event.target).css(transitionProp, '');

                    if (activeTransitions === 0 && callback) {
                        if (timeout) clearTimeout(timeout);
                        callback.call(context);
                    }
                }
            };

            if ($fromView) {
                activeTransitions++;

                // Registering transition end handler
                $fromView.one(that.transitionEndEvent, transitionEndHandler);

                // Setting transition css props
                $fromView.css(transitionProp, ['all', that.fromViewTransitionProps.duration, 's ',
                  that.fromViewTransitionProps.easing].join(''));

                $fromView.css({'-webkit-transition':'all ' + that.toViewTransitionProps.duration + 's ease-in-out'});
                $fromView.css({'transition':'all ' + that.toViewTransitionProps.duration + 's ease-in-out'});
            }

            if ($toView) {
                activeTransitions++;

                $toView.one(that.transitionEndEvent, transitionEndHandler);

                // Setting initial scale and opacity
                $toView.css({'opacity': 0, '-webkit-transform': 'scale3d(0.9,0.9,0.9)', 'transform':'scale3d(0.9,0.9,0.9)'});

                // Setting transition css props
                $toView.css({'-webkit-transition':'all ' + that.toViewTransitionProps.duration + 's ease-in-out'});
                $toView.css({'transition':'all ' + that.toViewTransitionProps.duration + 's ease-in-out'});

                // Showing the view
                $toView.css('visibility', 'visible');
            }

            // This is a hack to force DOM reflow before transition starts
            context.$el.css('width');

            // This is a fallback for situations when TransitionEnd event doesn't get triggered
            var transDuration = Math.max(that.fromViewTransitionProps.duration, that.toViewTransitionProps.duration) +
                Math.max(that.fromViewTransitionProps.delay, that.toViewTransitionProps.delay);

            timeout = setTimeout(function () {
                if (activeTransitions > 0) {
                    activeTransitions = -1;

                    console.log('Warning ' + that.transitionEndEvent + ' didn\'t trigger in expected time!');

                    if ($toView) {
                        $toView.off(that.transitionEndEvent, transitionEndHandler);
                        $toView.css(transitionProp, '');
                    }

                    if ($fromView) {
                        $fromView.off(that.transitionEndEvent, transitionEndHandler);
                        $fromView.css(transitionProp, '');
                    }

                    callback.call(context);
                }
            }, transDuration * 1.5 * 1000);

            if ($toView) $toView.css({'opacity':1, '-webkit-transform':'scale3d(1,1,1)', 'transform':'scale3d(1,1,1)'});
            if ($fromView) $fromView.css({'opacity':0, '-webkit-transform':'scale3d(0.9,0.9,0.9)', 'transform':'scale3d(0.9,0.9,0.9)'});
        }
    });

})(this, this.Encryptr);
