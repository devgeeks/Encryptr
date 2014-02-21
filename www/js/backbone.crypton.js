/*! Backbone.crypton - v0.1.0 - 2013-12-11

 * Copyright (c) 2013 tommy-carlos williams (devgeeks);
 * License: Apache2 (http://www.apache.org/licenses/LICENSE-2.0)
 */
 (function(window, console, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var debug     = function(msg) { console.log(msg); };
  var Backbone  = window.Backbone,
      _         = window._,
      $         = window.Zepto,
      crypton   = window.crypton;

  function S4(){
    return (((1+Math.random())*0x10000)|0).toString(16).substring(1);
  }
  
  function guid() {
    return (S4()+S4()+"-"+S4()+"-"+S4()+"-"+S4()+"-"+S4()+S4()+S4());
  }

  Backbone.sync = function(method, model, options) {
    var _this = this;
    var session = window.app.accountModel.get("session");
    var errorHandler = function (err, options) {
      debug("ERROR: " + err);
      return options.error && options.error(err);
    };
    var successHandler = function(resp) {
      return options.success && options.success(resp);
    };
    options = options || {};
    if (!session) {
      debug("ERROR: No available session");
      return options.error && options.error("No available session");
    }
    var containerName = model.container || options.container;
    if (!containerName) {
      debug("ERROR: No container specified");
      return options.error && options.error("No container specified");
    }

    debug(method);
    switch (method) {
      case "read":
        if (model.isNew && model.isNew()) {
          return successHandler(model.toJSON());
        }
        if (!model.isNew) {
          debug("Collection: This should not happen.");
          // Should we be calling model.collection.sync?
          return;
        }
        session.load(containerName, function(err, entries) {
          if (err) {
            return errorHandler(err, options);
          }
          entries.get(model[model.idAttribute], function(err, entry) {
            return successHandler(entry);
          });
        });
        break;
      case "create":
        session.load(containerName, function(err, entries) {
          if (err) return errorHandler(err, options);
          var modelId = model.modelId || guid();
          entries.add(modelId, function(err) {
            if (err) return errorHandler(err, options);
            entries.get(modelId, function(err, entry) {
              if (err) return errorHandler(err, options);
              var modelData = model.toJSON();
              modelData[model.idAttribute] = (modelData[model.idAttribute] ||
                                              modelId);
              for(var data in modelData) {
                if (modelData.hasOwnProperty(data)) {
                  entry[data] = modelData[data];
                }
              }

              entries.save(function(err) {
                if (err) return errorHandler(err, options);
                model[model.idAttribute] = modelId;
                return successHandler(entry);
              });
            });
          });
        });
        break;
      case "update":
        session.load(containerName, function(err, entries) {
          if (err) return errorHandler(err, options);
          entries.get(model[model.idAttribute], function(err, entry) {
            if (err) {
              if (err === "Key does not exist") {
                Backbone.sync("create", model, options);
                return;
              }
              return errorHandler(err, options);
            }

            for (var attribute in model.attributes) {
              if (attribute === model.idAttribute) continue;
              if (model.attributes.hasOwnProperty(attribute)) {
                entry[attribute] = model.attributes[attribute];
              }
            }
            entries.save(function(err) {
              if (err) return errorHandler(err, options);
              return successHandler(entry);
            });
          });
        });
        break;
      case "delete":
        session.load(containerName, function(err, entries) {
          if (err) return errorHandler(err, options);
          delete entries.keys[model[model.idAttribute]];
          if (model.isNew()) {
            return successHandler(false);
          }
          entries.save(function(err) {
            if (err) return errorHandler(err, options);
            return successHandler(true);
          });
        });
        break;
    }
  };

})(this, this.console);
