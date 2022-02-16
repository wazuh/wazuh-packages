"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.HttpService = void 0;

var _rxjs = require("rxjs");

var _operators = require("rxjs/operators");

var _std = require("@osd/std");

var _csp = require("../csp");

var _router = require("./router");

var _http_config = require("./http_config");

var _http_server = require("./http_server");

var _https_redirect_server = require("./https_redirect_server");

var _lifecycle_handlers = require("./lifecycle_handlers");

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

/** @internal */
class HttpService {
  constructor(coreContext) {
    this.coreContext = coreContext;

    _defineProperty(this, "httpServer", void 0);

    _defineProperty(this, "httpsRedirectServer", void 0);

    _defineProperty(this, "config$", void 0);

    _defineProperty(this, "configSubscription", void 0);

    _defineProperty(this, "logger", void 0);

    _defineProperty(this, "log", void 0);

    _defineProperty(this, "env", void 0);

    _defineProperty(this, "notReadyServer", void 0);

    _defineProperty(this, "internalSetup", void 0);

    _defineProperty(this, "requestHandlerContext", void 0);

    const {
      logger,
      configService,
      env
    } = coreContext;
    this.logger = logger;
    this.env = env;
    this.log = logger.get('http');
    this.config$ = (0, _rxjs.combineLatest)([configService.atPath(_http_config.config.path), configService.atPath(_csp.config.path)]).pipe((0, _operators.map)(([http, csp]) => new _http_config.HttpConfig(http, csp)));
    this.httpServer = new _http_server.HttpServer(logger, 'OpenSearchDashboards');
    this.httpsRedirectServer = new _https_redirect_server.HttpsRedirectServer(logger.get('http', 'redirect', 'server'));
  }

  async setup(deps) {
    this.requestHandlerContext = deps.context.createContextContainer();
    this.configSubscription = this.config$.subscribe(() => {
      if (this.httpServer.isListening()) {
        // If the server is already running we can't make any config changes
        // to it, so we warn and don't allow the config to pass through.
        this.log.warn('Received new HTTP config after server was started. Config will **not** be applied.');
      }
    });
    const config = await this.config$.pipe((0, _operators.first)()).toPromise();

    if (this.shouldListen(config)) {
      await this.runNotReadyServer(config);
    }

    const {
      registerRouter,
      ...serverContract
    } = await this.httpServer.setup(config);
    (0, _lifecycle_handlers.registerCoreHandlers)(serverContract, config, this.env);
    this.internalSetup = { ...serverContract,
      createRouter: (path, pluginId = this.coreContext.coreId) => {
        const enhanceHandler = this.requestHandlerContext.createHandler.bind(null, pluginId);
        const router = new _router.Router(path, this.log, enhanceHandler);
        registerRouter(router);
        return router;
      },
      registerRouteHandlerContext: (pluginOpaqueId, contextName, provider) => this.requestHandlerContext.registerContext(pluginOpaqueId, contextName, provider)
    };
    return this.internalSetup;
  } // this method exists because we need the start contract to create the `CoreStart` used to start
  // the `plugin` and `legacy` services.


  getStartContract() {
    return { ...(0, _std.pick)(this.internalSetup, ['auth', 'basePath', 'getServerInfo']),
      isListening: () => this.httpServer.isListening()
    };
  }

  async start() {
    const config = await this.config$.pipe((0, _operators.first)()).toPromise();

    if (this.shouldListen(config)) {
      if (this.notReadyServer) {
        this.log.debug('stopping NotReady server');
        await this.notReadyServer.stop();
        this.notReadyServer = undefined;
      } // If a redirect port is specified, we start an HTTP server at this port and
      // redirect all requests to the SSL port.


      if (config.ssl.enabled && config.ssl.redirectHttpFromPort !== undefined) {
        await this.httpsRedirectServer.start(config);
      }

      await this.httpServer.start();
    }

    return this.getStartContract();
  }
  /**
   * Indicates if http server has configured to start listening on a configured port.
   * We shouldn't start http service in two cases:
   * 1. If `server.autoListen` is explicitly set to `false`.
   * 2. When the process is run as dev cluster master in which case cluster manager
   * will fork a dedicated process where http service will be set up instead.
   * @internal
   * */


  shouldListen(config) {
    return !this.coreContext.env.isDevClusterMaster && config.autoListen;
  }

  async stop() {
    if (this.configSubscription === undefined) {
      return;
    }

    this.configSubscription.unsubscribe();
    this.configSubscription = undefined;

    if (this.notReadyServer) {
      await this.notReadyServer.stop();
    }

    await this.httpServer.stop();
    await this.httpsRedirectServer.stop();
  }

  async runNotReadyServer(config) {
    this.log.debug('starting NotReady server');
    const httpServer = new _http_server.HttpServer(this.logger, 'NotReady');
    const {
      server
    } = await httpServer.setup(config);
    this.notReadyServer = server; // use hapi server while OpenSearchDashboardsResponseFactory doesn't allow specifying custom headers
    // https://github.com/elastic/kibana/issues/33779

    this.notReadyServer.route({
      path: '/{p*}',
      method: '*',
      handler: (req, responseToolkit) => {
        this.log.debug(`Wazuh dashboard server is not ready yet ${req.method}:${req.url.href}.`); // If server is not ready yet, because plugins or core can perform
        // long running tasks (build assets, saved objects migrations etc.)
        // we should let client know that and ask to retry after 30 seconds.

        return responseToolkit.response('Wazuh dashboard server is not ready yet').code(503).header('Retry-After', '30');
      }
    });
    await this.notReadyServer.start();
  }

}

exports.HttpService = HttpService;