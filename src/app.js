var Encryptr = (function (window, console, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
      _         = window._,
      $         = window.Zepto;

  var Encryptr = function () {
    this.online = true; // assume a hopeful default
  };

  Encryptr.prototype.init = function() {
    window.document.addEventListener("deviceready", this.onDeviceReady, false);
    window.document.addEventListener("resume", this.onResume, false);
    window.document.addEventListener("pause", this.onPause, false);
    window.document.addEventListener("offline", this.setOffline, false);
    window.document.addEventListener("online", this.setOnline, false);

    var settings = window.localStorage.getItem("settings") || "{}";
    window.app.settings = JSON.parse(settings);

    // Set the hostname for the Crypton server
    // window.crypton.host = "192.168.1.12";
    window.crypton.host = "localhost";

    window.Offline.options =
          {checks: {image: {url: "https://crypton.io/images/crypton.png"}}};

    var isNodeWebkit = (typeof process == "object");
    if (isNodeWebkit) $.os.nodeWebkit = true;
    // Render the login view (and bind its events)
    this.loginView = new this.LoginView().render();
    // Hax for Android 2.x not groking :active
    $(document).on("touchstart", "a", function(event) {
      var $this = $(this);
      $this.addClass("active");
    });
    $(document).on("touchend", "a", function(event) {
      var $this = $(this);
      $this.removeClass("active");
    });
    $(document).on("touchmove", "a", function(event) {
      var $this = $(this);
      $this.removeClass("active");
    });

    window.FastClick.attach(document.body);
  };

  Encryptr.prototype.onDeviceReady = function(event) {
    if (window.device && window.device.platform === "iOS" && parseFloat(window.device.version) >= 7.0) {
      window.document.querySelectorAll(".app")[0].style.top = "20px"; // status bar hax
    }
    if (window.StatusBar && $.os.ios) {
      window.StatusBar.styleLightContent();
    }
    // Backstack effects
    Encryptr.prototype.noEffect = new window.BackStack.NoEffect();
    Encryptr.prototype.fadeEffect = new window.BackStack.FadeEffect();
    Encryptr.prototype.defaultEffect = new window.BackStack.NoEffect();
    Encryptr.prototype.defaultPopEffect = new window.BackStack.NoEffect();
    if (window.device && window.device.platform === "iOS") {
      Encryptr.prototype.defaultEffect = new Encryptr.prototype.FastSlideEffect();
      Encryptr.prototype.defaultPopEffect = new Encryptr.prototype.FastSlideEffect({
        direction: "right"
      });
    }
    window.document.addEventListener("backbutton", Encryptr.prototype.onBackButton, false);
    window.document.addEventListener("menubutton", Encryptr.prototype.onMenuButton, false);

    // Platform specific clipboard plugin / code
    if ($.os.ios || $.os.android) {
      Encryptr.prototype.copyToClipboard = window.cordova.plugins.clipboard.copy;
    } else if ($.os.bb10) {
      Encryptr.prototype.copyToClipboard = window.community.clipboard.setText;
    } else if ($.os.nodeWebkit && window.require ) { // How to *actually* detect node-webkit ?
      var gui = window.require('nw.gui');
      window.clipboard = gui.Clipboard.get();
      Encryptr.prototype.copyToClipboard = function(text) {
        window.clipboard.set(text, 'text');
      };
    } else {
      // Fallback to empty browser polyfill
      Encryptr.prototype.copyToClipboard = function() {};
    }
  };

  Encryptr.prototype.setOffline = function(event) {
    this.online = false;
  };

  Encryptr.prototype.setOnline = function(event) {
    this.online = true;
  };

  Encryptr.prototype.onResume = function(event) {
    // Throw up the login screen
    window.app.loginView.show();
    window.setTimeout(function() {
      window.app.session = undefined;
      window.app.navigator.popAll(window.app.noEffect);
      window.app.mainView.menuView.close();
    },100);
  };

  Encryptr.prototype.onPause = function(event) {
    // ...
  };

  Encryptr.prototype.onBackButton = function(event) {
    if ($(".menu").is(":visible")) {
      window.app.mainView.menuView.dismiss();
      return;
    }
    if ($(".addMenu").is(":visible")) {
      window.app.mainView.addMenuView.dismiss();
      return;
    }
    if ($(".back-btn").is(":visible")) {
      window.app.navigator.popView(window.app.defaultPopEffect);
      return;
    }
    navigator.app.exitApp();
  };

  Encryptr.prototype.onMenuButton = function(event) {
    // ...
  };

  /** Prepare session-unique counter for internal use by .getNewUnique().
   *
   * Depends on established login, specifically, window.app.session.
   *
   * @param (deferred) ready (optional) .resolve()s when counter is ready.
   */
  Encryptr.prototype.establishCounter = function (ready) {
    window.cryptonutils.loadOrCreateContainer(
      "_uCounter",
      window.app.session,
      function (container) {
        window.app._uCounter = container;
        window.cryptonutils.getOrCreateSetting(
          container, "counter", 1,
          function (setting) {
            if (ready) {
              ready.resolve();
            }
          },
          function (errmsg) {
            console.log("Failed to set unique counter: " + errmsg);
          });
      },
      function (errmsg) {
        console.log("Failed to establish unique counter: " + errmsg);
      });
  };
  /** Return a new session-unique integer. */
  Encryptr.prototype.getNewUnique = function() {
    if (! window.app.session) {
      throw new Error("Session counter increment attempted without session");
    }
    else if (! window.app._uCounter || ! window.app._uCounter.keys.counter) {
      throw new Error("Session counter not properly established");
    }
    window.app._uCounter.keys.counter += 1;
    window.app._uCounter.save(
      function (err) {
        if (err) {
          // Not a lot we can do.
          console.log("Failed to save unique counter!");
        }
      }
    );
    return window.app._uCounter.keys.counter;
  };

  Encryptr.prototype.randomString = function(length) {
    var charset = "!@#$%^&*()_+{}:<>?|,[];./~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    var i;
    var result = "";
    if(window.crypto && window.crypto.getRandomValues) {
      var values = new Uint32Array(length);
      window.crypto.getRandomValues(values);
      for(i = 0; i < length; i++) {
          result += charset[values[i] % charset.length];
      }
    }
    return result; // If you can't say something nice, don's say anything at all
  };

  return Encryptr;

})(this, this.console);
