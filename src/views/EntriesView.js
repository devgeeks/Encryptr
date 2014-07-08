(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
  _         = window._,
  $         = window.Zepto;

  var EntriesView = Backbone.View.extend({
    destructionPolicy: "never",
    events: {
      // ...
    },
    initialize: function() {
      _.bindAll(this, "render", "addAll", "addOne", "viewActivate",
        "viewDeactivate");
      this.collection.bind("reset", this.addAll, this);
      this.collection.bind("add", this.addOne, this);
      this.collection.bind("remove", this.addAll, this);
      this.on("viewActivate",this.viewActivate);
      this.on("viewDeactivate",this.viewDeactivate);

      this.subViews = [];
      this.hasItems = false;
    },
    render: function() {
      this.$el.html(window.tmpl["entriesView"]({}));
      return this;
    },
    addAll: function () {
      this.$(".entriesViewLoading").removeClass("loadingEntries");
      if (this.collection.models.length === 0) {
        window.setTimeout(function() {
          $(".emptyEntries").show();
        }, 300);
      } else {
        $(".emptyEntries").hide();
      }
      this.$(".entries").html("");
      this.collection.each(this.addOne);
    },
    addOne: function(model) {
      $(".emptyEntries").hide();
      this.$(".entriesViewLoading").removeClass("loadingEntries");
      if (this.collection.models.length === 0) {
        window.setTimeout(function() {
          $(".emptyEntries").show();
        }, 300);
      } else {
        $(".emptyEntries").hide();
      }
      var view = new Encryptr.prototype.EntriesListItemView({
        model: model
      });
      this.$(".entries").append(view.render().el);
      this.subViews.push(view);
    },
    viewActivate: function(event) {
      var _this = this,
          rootContainerID = window.app.rootContainerID;
      this.collection.fetch({
        container: rootContainerID,
        success: function(entries) {
          if (entries.length === 0) {
            _this.addAll();
          }
        }, error: function(err) {
          window.app.session.create(rootContainerID, function(err, container) {
            if (err) {
              // OK. This is a bit more serious...
              console.log(err);
              window.app.dialogAlertView.show({
                title: "Critical Error",
                subtitle: err
              }, function() {
                console.log("could not even recreate the container...");
              });
              return;
            }
            // the container should exist now...
            _this.viewActivate(event);
          });
        }
      });
    },
    viewDeactivate: function(event) {
      // ...
    },
    close: function() {
      _.each(this.subViews, function(view) {
        view.close();
      });
      this.remove();
    }
  });
  Encryptr.prototype.EntriesView = EntriesView;

  var EntriesListItemView = Backbone.View.extend({
    tagName: "li",
    className: "entry",
    events: {
      "click a": "a_clickHandler"
    },
    initialize: function() {
      _.bindAll(this, "render");
      this.model.bind("change", this.render, this);
    },
    render: function() {
      this.$el.html(
        window.tmpl["entriesListItemView"](
          this.model.toJSON()
        )
      );
      return this;
    },
    a_clickHandler: function(event) {
      var _this = this;
      if (!$(".menu").hasClass("dismissed") ||
            !$(".addMenu").hasClass("dismissed")) {
        return;
      }
      window.app.navigator.pushView(window.app.EntryView, {
        model: _this.model
      }, window.app.defaultEffect);
    },
    close: function() {
      this.remove();
    }
  });
  Encryptr.prototype.EntriesListItemView = EntriesListItemView;

})(this, this.console, this.Encryptr);
