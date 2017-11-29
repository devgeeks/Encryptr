(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
  _         = window._,
  $         = window.Zepto;

  var EntryView = Backbone.View.extend({
    events: {
      "longTap .copyable": "copyable_longTapHandler",
      "dblclick .copyable": "copyable_doubleTapHandler",
      "doubleTap .copyable": "copyable_doubleTapHandler",
      "click .eye": "eye_clickHandler"
    },
    initialize: function() {
      _.bindAll(this,
          "render",
          "showEditDelete",
          "editButton_clickHandler",
          "deleteButton_clickHandler",
          "copyable_doubleTapHandler",
          "viewActivate",
          "viewDeactivate");
      app.checkonline(['.btn.delete-btn', '.btn.edit-btn']);
      this.model.on("change", this.addAll, this);
      this.on("viewActivate",this.viewActivate);
      this.on("viewDeactivate",this.viewDeactivate);
      window.app.mainView.on("deleteentry", this.deleteButton_clickHandler, this);
      window.app.mainView.once("editentry", this.editButton_clickHandler, this);
      if (!window.app.toastView) {
        window.app.toastView = new window.app.ToastView();
      }
    },
    render: function() {
      var _this = this;
      this.$el.html(
        window.tmpl["entryView"](
          this.model.toJSON()
        )
      );
      if (this.model.get("items")) {
        _this.$(".entriesViewLoading").removeClass("loadingEntries");
        _this.showEditDelete();
      }

      // this.model.fetch();

      return this;
    },
    showEditDelete: function() {
      if (!$('.loadingEntries').length) {
        $(".nav .edit-btn.right").removeClass("hidden");
        $(".nav .delete-btn").removeClass("hidden");
      }
    },
    addAll: function() {
      var _this = this;
      this.$el.html(
        window.tmpl["entryView"](
          this.model.toJSON()
        )
      );
      if (this.model.get("items")) {
        _this.$(".entriesViewLoading").removeClass("loadingEntries");
        _this.showEditDelete();
      }
      // Desktop polyfill for longTap
      var timer = null;
      this.$(".copyable").on("mousedown", function(event) {
        timer = setTimeout( function() {
          _this.copyable_longTapHandler(event);
        }, 750 );
      });
      this.$(".copyable").on("mouseup", function(event) {
        clearTimeout( timer );
      });
    },
    copyable_longTapHandler: function(event) {
      event.preventDefault();
      event.stopPropagation();
      var type = $(event.target).attr('data-type');
      var key;
      if (type === 'Label') {
        key = { value: this.model.toJSON().label };
      } else {
        key = _.findWhere(this.model.get("items"), { key: type });
      }
      window.app.copyToClipboard(key.value);
      window.app.toastView.show("Copied " + type);
    },
    copyable_doubleTapHandler: function(event) {
      this.copyable_longTapHandler(event);
    },
    eye_clickHandler: function(event) {
      var $this = $(event.target);
      $this.toggleClass('revealed');
      $this.closest('li').find('.copyable').toggleClass('password');
    },
    editButton_clickHandler: function(event) {
      window.app.navigator.replaceView(
        window.app.EditView,
        {model: this.model},
        window.app.defaultEffect
      );
    },
    deleteButton_clickHandler: function(event) {
      var _this = this;
      window.app.dialogConfirmView.show({
        title: "Deleting item",
        subtitle: "Are you sure you want to delete this item?"
      }, function(event) {
        if (event.type === "dialogAccept") {
          $(".blocker").show();
          var oldId = _this.model.id;
          var parentCollection = _this.model.collection;
          if (!parentCollection){
            parentCollection = window.app.entriesCollection;
          }
          _this.model.destroy({success: function(model, response) {
            window.app.session.load("_encryptrIndex", function(err, container) {
              if (err) {
                $(".blocker").hide();
                window.app.dialogAlertView.show({
                  title: "Error",
                  subtitle: err
                }, function(){});
                return;
              }
              delete container.keys[oldId];
              container.save(function(err) {
                if (err) {
                  $(".blocker").hide();
                  window.app.dialogAlertView.show({
                    title: "Error",
                    subtitle: err
                  }, function(){});
                }
                $(".blocker").hide();
                parentCollection.fetch({
                  success: function() {
                    var indexJSON = JSON.stringify(parentCollection.toJSON());
                    if (window.app.accountModel.get("passphrase")) {
                      var encryptedIndexJSON = window.sjcl.encrypt(
                        window.app.accountModel.get("passphrase"), indexJSON,
                        window.crypton.cipherOptions
                      );
                      var username = window.app.accountModel.get("username");
                      var hashArray = window.sjcl.hash.sha256.hash(username);
                      var hash = window.sjcl.codec.hex.fromBits(hashArray);
                      window.localStorage.setItem("encryptr-" + hash + "-index", encryptedIndexJSON);
                    }
                    window.app.navigator.popView(window.app.defaultPopEffect);
                    window.setTimeout(function(){
                      window.app.entriesView.fixRecord(_this.model, console.error, function(){
                        window.app.toastView.show("Item deleted");
                        window.app.mainView.updatedLocalStorage = false;
                        window.app.mainView.updateLocalStorage();
                      }, {});
                    }, 100);
                  }
                });
              }, {force: true, save: true});
            });
          }, error: function(err) {
            window.app.dialogAlertView.show({
              title: "Error",
              subtitle: err
            }, function(){});
          }});
        }
      });
    },
    viewActivate: function(event) {
      var _this = this;
      $('.subviews').scrollTop(0);
      _this.model.fetch({success: function() {
        _this.$(".entriesViewLoading").removeClass("loadingEntries");
        _this.showEditDelete();
      }, error: function(err) {
        // error out and return to the entries screen
        console.log(err);
      }});
      window.app.mainView.backButtonDisplay(true);
      $(".nav .btn.right").addClass("hidden");
      window.setTimeout(function() {
        _this.showEditDelete();
      },200);
      window.app.mainView.setTitle(_this.model.get("type"));
    },
    viewDeactivate: function(event) {
      $(".nav .btn.right").addClass("hidden");
      $(".nav .add-btn.right").removeClass("hidden");
      window.app.mainView.setTitle("Encryptr");
      window.app.mainView.off("editentry", null, null);
      window.app.mainView.off("deleteentry", null, null);
    },
    close: function() {
      this.remove();
    }
  });
  Encryptr.prototype.EntryView = EntryView;

})(this, this.console, this.Encryptr);
