(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _           = window._,
    $           = window.Zepto;

  var EntriesCollection = Backbone.Collection.extend({
    initialize: function(models, options) {
      var rootContainerID = window.app.rootContainerID;
      this.container = options && options.container || rootContainerID;
      this.model = Encryptr.prototype.EntryModel; // default
    },
    fetch: function (options) {
      var _this = this;
      window.app.session.load(this.container, function(err, container) {
        if (options && options.error && err) options.error(err);
        if (err) return;
        _this.set(
          _.map(container.keys, function(value, key) {
            return new _this.model({
              id: key,
              label: value.label,
              type: value.type
            });
          })
        );
        if (options && options.success) options.success(_this);
      });
    },
    sync: function() {
      // @TODO: EntriesCollection.sync
    }
  });

  Encryptr.prototype.EntriesCollection = EntriesCollection;

})(this, this.console, this.Encryptr);
