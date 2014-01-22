(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _           = window._,
    $           = window.Zepto;

  var EntriesCollection = Backbone.Collection.extend({
    rootContainerID: "entries",
    initialize: function() {
      this.container = this.rootContainerID; // default
      this.model = Encryptr.prototype.EntryModel; // default
    },
    fetch: function (options) {
      var _this = this;
      var container = (options && options.container) || this.container;
      window.app.session.load(container, function(err, entries) {
        if (err) {
          if (options && options.error) {
            options.error(err);
          }
          else {
            console.log("EntriesCollection.fetch(): " + err);
          }
          return;
        }
        _this.set(
          _.map(entries.keys, function(entry, key){
            var it;
            if (entry.type === "Folder") {
              it = new Encryptr.prototype.FolderModel(entry);
            }
            else {
              it = new _this.model(entry);
            }
            it.container = container;
            return it;
          })
        );
      });
    },
    which: "EntriesCollection"
  });

  Encryptr.prototype.EntriesCollection = EntriesCollection;

})(this, this.console, this.Encryptr);
