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
    document.addEventListener('dragover', function(e){
      e.preventDefault();
      e.stopPropagation();
    },  false);
    document.addEventListener('drop', function(e){
      e.preventDefault();
      e.stopPropagation();
    }, false);

    var settings = window.localStorage.getItem("settings") || "{}";
    window.app.settings = JSON.parse(settings);

    // Set the hostname for the Crypton server
    // window.crypton.host = "192.168.1.12";
    window.crypton.host = "localhost";
    window.crypton.port = 1025;

    window.Offline.options = {
      // Should we check the connection status immediatly on page load.
      checkOnLoad: false,

      // Should we monitor AJAX requests to help decide if we have a connection.
      interceptRequests: true,

      // Should we automatically retest periodically when the connection is
      // down (set to false to disable).
      reconnect: {
        // How many seconds should we wait before rechecking.
        initialDelay: 3
      },

      // Should we store and attempt to remake requests which fail while the
      // connection is down.
      requests: true,

      // Should we show a snake game while the connection is down to keep
      // the user entertained?
      // It's not included in the normal build, you should bring in
      // js/snake.js in addition to offline.min.js.
      game: false,

      // What the xhr checks
      checks: {
        xhr: {
          url: ("https://" +
                window.crypton.host +
                (window.crypton.port ? (":" + window.crypton.port) : "") +
                "/")
        }
      }
    };

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
    $(document).on("touchcancel", "a", function(event) {
      var $this = $(this);
      $this.removeClass("active");
    });
    $(document).on("touchmove", "a", function(event) {
      var $this = $(this);
      $this.removeClass("active");
    });

    this.dialogConfirmView = new Encryptr.prototype.DialogConfirmView().render();
    this.dialogConfirmView.dismiss();
    $("#main").append(this.dialogConfirmView.el);
    this.dialogAlertView = new Encryptr.prototype.DialogAlertView().render();
    this.dialogAlertView.dismiss();
    $("#main").append(this.dialogAlertView.el);

    window.FastClick.attach(document.body);
  };

  Encryptr.prototype.onDeviceReady = function(event) {
    // Useragent sniffin. Ew.
    if (navigator.userAgent.match(/(iPad|iPhone);.*CPU.*OS 7_\d/i)) {
      $(".app").css({"top":"20px"});
    }
    if (window.StatusBar && $.os.ios) {
      window.StatusBar.styleLightContent();
    }
    // Backstack effects
    Encryptr.prototype.noEffect = new window.BackStack.NoEffect();
    Encryptr.prototype.fadeEffect = new window.BackStack.FadeEffect();
    Encryptr.prototype.defaultEffect = new Encryptr.prototype.PopFadeEffect();
    Encryptr.prototype.defaultPopEffect = new Encryptr.prototype.PopFadeEffect({
      direction: "right"
    });
    window.document.addEventListener("backbutton",
                                     Encryptr.prototype.onBackButton, false);
    window.document.addEventListener("menubutton",
                                     Encryptr.prototype.onMenuButton, false);

    window.app.checkVersion();

    if (!$.os.nodeWebkit) {
      // overflow: auto !important; -webkit-overflow-scrolling: touch;
      $(".subviews").css({
        "overflow":"auto !important",
        "-webkit-overflow-scrolling":"touch"
      });
    }
    // Platform specific clipboard plugin / code
    if ($.os.ios || $.os.android) {
      Encryptr.prototype.copyToClipboard = window.cordova.plugins.clipboard.copy;
    } else if ($.os.bb10) {
      Encryptr.prototype.copyToClipboard = window.community.clipboard.setText;
    // How to *actually* detect node-webkit ?
    } else if ($.os.nodeWebkit && window.require ) {
      /* jshint node: true */
      var gui = require('nw.gui');
      var win = gui.Window.get();
      if (process.platform === "darwin") {
        var nativeMenuBar = new gui.Menu({ type: "menubar" });
        nativeMenuBar.createMacBuiltin("Encryptr");
        win.menu = nativeMenuBar;
      }
      var option = {
        key : "Ctrl+F",
        active : function() {
          if ($("input.search").length > 0) {
            $("input.search").focus();
          }
        },
        failed : function(msg) {
          // :(, fail to register the |key| or couldn't parse the |key|.
          console.log(msg);
        }
      };
      // Create a shortcut with |option|.
      var shortcut = new gui.Shortcut(option);
      gui.App.registerGlobalHotKey(shortcut);
      // ...but turn it off when not focused
      win.on("blur", function() {
        gui.App.unregisterGlobalHotKey(shortcut);
      });
      win.on("focus", function() {
        gui.App.registerGlobalHotKey(shortcut);
      });

      window.clipboard = gui.Clipboard.get();
      Encryptr.prototype.copyToClipboard = function(text) {
        window.clipboard.set(text, 'text');
      };
      /* jshint node: false */
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
    // Logging out seems a bit overkill
    // For now, put a 10 minute timeout on it...
    var timeoutInMinutes =
      Math.floor(((Date.now() - window.app.lastPaused) / 1000) / 60);
    if (timeoutInMinutes >= 10) {
      window.app.accountModel.logout(function() {
        window.app.loginView.disable();
        // Throw up the login screen
        window.app.loginView.show();
        window.setTimeout(function() {
          window.app.navigator.popAll(window.app.noEffect);
          window.app.mainView.close();
        },100);
        window.setTimeout(function() {
          window.app.loginView.enable();
        },350);
        window.setTimeout(window.app.checkVersion,1000);
      });
    }
  };

  Encryptr.prototype.onPause = function(event) {
    window.app.lastPaused = Date.now();
  };

  Encryptr.prototype.onBackButton = function(event) {
    if ($(".dialogAlert").is(":visible")) {
      window.app.dialogAlertView.dismiss();
      return;
    }
    if ($(".dialogConfirm").is(":visible")) {
      window.app.dialogConfirmView.dismiss();
      return;
    }
    if ($(".menu").is(":visible")) {
      window.app.mainView.menuView.dismiss();
      return;
    }
    if ($(".addMenu").is(":visible")) {
      window.app.mainView.addMenuView.dismiss();
      return;
    }
    if ($(".back-btn").is(":visible")) {
      if (window.app.navigator.activeView.confirmBackNav) {
        window.app.dialogConfirmView.show(window.app.navigator.activeView.confirmBackNav,
            function(event) {
              if (event.type === "dialogAccept") {
                if (window.app.navigator.viewsStack.length > 1) {
                  window.app.mainView.backButtonDisplay(false);
                  window.app.navigator.popView(window.app.defaultPopEffect);
                }
                window.app.navigator.activeView.confirmBackNav.callback();
              }
            });
      } else {
        if (window.app.navigator.viewsStack.length > 1) {
          window.app.mainView.backButtonDisplay(false);
          window.app.navigator.popView(window.app.defaultPopEffect);
        }
      }
      return;
    }
    navigator.app.exitApp();
  };

  Encryptr.prototype.onMenuButton = function(event) {
    // ...
  };

  Encryptr.prototype.checkVersion = function(ignoreOptional) {
    var buster = Date.now();
    $.getJSON("https://encryptr.org/_latestVersion.json?v=" + buster, function(versionData) {
      var latestVersion = window.semver.gte(window.app.version, versionData.tag_name);
      if (!latestVersion) {
        if (ignoreOptional && versionData.priority === "optional") {
          return;
        }
        window.app.dialogConfirmView.show({
          title: "New version available",
          subtitle: "The new " + versionData.tag_name + " release is " +
              versionData.priority + ". Would you like to download it now?"
        },
        function(event) {
          if (event.type === "dialogAccept") {
            if ($.os.nodeWebkit) {
              window.require('nw.gui').Shell.openExternal(versionData.url);
              return false;
            }
            window.open(versionData.url, "_system");
          }
        });
      }
    });
  };

  Encryptr.prototype.randomString = function(length) {
    var charset = "!@#$%^*()_+{}:?|,[];./~ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
      "abcdefghijklmnopqrstuvwxyz0123456789";
    var i;
    var result = "";
    var max = charset.length - 1;
    if(window.crypto && window.crypto.getRandomValues) {
      for(i = 0; i < length; i++) {
        result += charset[Encryptr.randomInt(0, max)];
      }
    }
    return result; // If you can't say something nice, don't say anything at all
  };
  
  Encryptr.prototype.randomInt = function(min, max) {
    var i = rval = bits = bytes = 0;
    var range = max - min;
    if (range < 1) {
      return min;
    }
    if (window.crypto && window.crypto.getRandomValues) {
      // Calculate Math.ceil(Math.log(range, 2)) using binary operators
      var tmp = range;
      /**
       * mask should be, in binary, a string of 1s that we can & with our random
       * value to reduce the number of lookups
       */
      var mask = 1;
      while (tmp > 0) {
        if (bits % 8 === 0) {
          bytes++;
        }
        bits++;
        mask = mask << 1 | 1;
        tmp >>= 1;
      }
      
      var values = new Uint8Array(bytes);
      do {
        window.crypto.getRandomValues(values);
        
        // Turn the random bytes into an integer
        rval = 0;
        for (i = 0; i < bytes; i++) {
          rval |= (values[i] << (8 * i));
        }
        // Apply the mask
        rval &= mask;
      } while(rval > range);
      
      // We should return a value in the interval [min, max]
      return (rval + min);
    }
  };

  return Encryptr;

})(this, this.console);
