import { __awaiter } from "tslib";
import { AuthSubject } from './auth-subject';
import { AuthActionBuilder } from './auth-action';
import { IonicUserInfoHandler } from './user-info-request-handler';
import { IonicEndSessionHandler } from './end-session-request-handler';
import { IonicAuthorizationRequestHandler, AUTHORIZATION_RESPONSE_KEY } from './authorization-request-handler';
import { DefaultBrowser } from "./auth-browser";
import { BaseTokenRequestHandler, AuthorizationServiceConfiguration, AuthorizationNotifier, TokenResponse, AuthorizationRequest, DefaultCrypto, GRANT_TYPE_AUTHORIZATION_CODE, TokenRequest, GRANT_TYPE_REFRESH_TOKEN, LocalStorageBackend, JQueryRequestor } from '@openid/appauth';
import { EndSessionRequest } from './end-session-request';
import { AuthObserver, ActionHistoryObserver, SessionObserver } from './auth-observer';
const TOKEN_RESPONSE_KEY = "token_response";
const AUTH_EXPIRY_BUFFER = 10 * 60 * -1; // 10 mins in seconds
export class AuthService {
    constructor(browser = new DefaultBrowser(), storage = new LocalStorageBackend(), requestor = new JQueryRequestor()) {
        this.browser = browser;
        this.storage = storage;
        this.requestor = requestor;
        this._authSubject = new AuthSubject();
        this._actionHistory = new ActionHistoryObserver();
        this._session = new SessionObserver();
        this.tokenHandler = new BaseTokenRequestHandler(requestor);
        this.userInfoHandler = new IonicUserInfoHandler(requestor);
        this.requestHandler = new IonicAuthorizationRequestHandler(browser, storage);
        this.endSessionHandler = new IonicEndSessionHandler(browser);
        this.setupAuthorizationNotifier();
        this.addActionObserver(this._actionHistory);
        this.addActionObserver(this._session);
    }
    get authConfig() {
        if (!this._authConfig)
            throw new Error("AuthConfig Not Defined");
        return this._authConfig;
    }
    set authConfig(value) {
        this._authConfig = value;
    }
    get configuration() {
        if (!this._configuration) {
            return AuthorizationServiceConfiguration.fetchFromIssuer(this.authConfig.server_host, this.requestor)
                .catch(() => { throw new Error("Unable To Obtain Server Configuration"); });
        }
        if (this._configuration != undefined) {
            return Promise.resolve(this._configuration);
        }
        else {
            throw new Error("Unable To Obtain Server Configuration");
        }
    }
    get history() {
        return this._actionHistory.history.slice(0);
    }
    get session() {
        return this._session.session;
    }
    notifyActionListers(action) {
        this._authSubject.notify(action);
    }
    setupAuthorizationNotifier() {
        let notifier = new AuthorizationNotifier();
        this.requestHandler.setAuthorizationNotifier(notifier);
        notifier.setAuthorizationListener((request, response, error) => this.onAuthorizationNotification(request, response, error));
    }
    onAuthorizationNotification(request, response, error) {
        let codeVerifier = (request.internal != undefined && this.authConfig.pkce) ? request.internal.code_verifier : undefined;
        if (response != null) {
            this.requestAccessToken(response.code, codeVerifier);
        }
        else if (error != null) {
            throw new Error(error.errorDescription);
        }
        else {
            throw new Error("Unknown Error With Authentication");
        }
    }
    internalAuthorizationCallback(url) {
        return __awaiter(this, void 0, void 0, function* () {
            this.browser.closeWindow();
            yield this.storage.setItem(AUTHORIZATION_RESPONSE_KEY, url);
            return this.requestHandler.completeAuthorizationRequestIfPossible();
        });
    }
    internalEndSessionCallback() {
        return __awaiter(this, void 0, void 0, function* () {
            this.browser.closeWindow();
            yield this.storage.removeItem(TOKEN_RESPONSE_KEY);
            this.notifyActionListers(AuthActionBuilder.SignOutSuccess());
        });
    }
    performEndSessionRequest(state) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.session.token != undefined) {
                let requestJson = {
                    postLogoutRedirectURI: this.authConfig.end_session_redirect_url,
                    idTokenHint: this.session.token.idToken || '',
                    state: state || undefined,
                };
                let request = new EndSessionRequest(requestJson);
                let returnedUrl = yield this.endSessionHandler.performEndSessionRequest(yield this.configuration, request);
                //callback may come from showWindow or via another method
                if (returnedUrl != undefined) {
                    this.endSessionCallback();
                }
            }
            else {
                //if user has no token they should not be logged in in the first place
                this.endSessionCallback();
            }
        });
    }
    performAuthorizationRequest(authExtras, state) {
        return __awaiter(this, void 0, void 0, function* () {
            let requestJson = {
                response_type: AuthorizationRequest.RESPONSE_TYPE_CODE,
                client_id: this.authConfig.client_id,
                redirect_uri: this.authConfig.redirect_url,
                scope: this.authConfig.scopes,
                extras: authExtras,
                state: state || undefined,
            };
            let request = new AuthorizationRequest(requestJson, new DefaultCrypto(), this.authConfig.pkce);
            if (this.authConfig.pkce)
                yield request.setupCodeVerifier();
            return this.requestHandler.performAuthorizationRequest(yield this.configuration, request);
        });
    }
    requestAccessToken(code, codeVerifier) {
        return __awaiter(this, void 0, void 0, function* () {
            let requestJSON = {
                grant_type: GRANT_TYPE_AUTHORIZATION_CODE,
                code: code,
                refresh_token: undefined,
                redirect_uri: this.authConfig.redirect_url,
                client_id: this.authConfig.client_id,
                extras: (codeVerifier) ? {
                    "code_verifier": codeVerifier
                } : {}
            };
            let token = yield this.tokenHandler.performTokenRequest(yield this.configuration, new TokenRequest(requestJSON));
            yield this.storage.setItem(TOKEN_RESPONSE_KEY, JSON.stringify(token.toJson()));
            this.notifyActionListers(AuthActionBuilder.SignInSuccess(token));
        });
    }
    requestTokenRefresh() {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.session.token) {
                throw new Error("No Token Defined!");
            }
            let requestJSON = {
                grant_type: GRANT_TYPE_REFRESH_TOKEN,
                refresh_token: (_a = this.session.token) === null || _a === void 0 ? void 0 : _a.refreshToken,
                redirect_uri: this.authConfig.redirect_url,
                client_id: this.authConfig.client_id,
            };
            let token = yield this.tokenHandler.performTokenRequest(yield this.configuration, new TokenRequest(requestJSON));
            yield this.storage.setItem(TOKEN_RESPONSE_KEY, JSON.stringify(token.toJson()));
            this.notifyActionListers(AuthActionBuilder.RefreshSuccess(token));
        });
    }
    internalLoadTokenFromStorage() {
        return __awaiter(this, void 0, void 0, function* () {
            let token;
            let tokenResponseString = yield this.storage.getItem(TOKEN_RESPONSE_KEY);
            if (tokenResponseString != null) {
                token = new TokenResponse(JSON.parse(tokenResponseString));
                if (token) {
                    return this.notifyActionListers(AuthActionBuilder.LoadTokenFromStorageSuccess(token));
                }
            }
            throw new Error("No Token In Storage");
        });
    }
    internalRequestUserInfo() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.session.token) {
                let userInfo = yield this.userInfoHandler.performUserInfoRequest(yield this.configuration, this.session.token);
                this.notifyActionListers(AuthActionBuilder.LoadUserInfoSuccess(userInfo));
            }
            else {
                throw new Error("No Token Available");
            }
        });
    }
    loadTokenFromStorage() {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.internalLoadTokenFromStorage().catch((response) => {
                this.notifyActionListers(AuthActionBuilder.LoadTokenFromStorageFailed(response));
            });
        });
    }
    signIn(authExtras, state) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.performAuthorizationRequest(authExtras, state).catch((response) => {
                this.notifyActionListers(AuthActionBuilder.SignInFailed(response));
            });
        });
    }
    signOut(state) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.performEndSessionRequest(state).catch((response) => {
                this.notifyActionListers(AuthActionBuilder.SignOutFailed(response));
            });
        });
    }
    refreshToken() {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.requestTokenRefresh().catch((response) => {
                this.storage.removeItem(TOKEN_RESPONSE_KEY);
                this.notifyActionListers(AuthActionBuilder.RefreshFailed(response));
            });
        });
    }
    loadUserInfo() {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.internalRequestUserInfo().catch((response) => {
                this.notifyActionListers(AuthActionBuilder.LoadUserInfoFailed(response));
            });
        });
    }
    authorizationCallback(callbackUrl) {
        this.internalAuthorizationCallback(callbackUrl).catch((response) => {
            this.notifyActionListers(AuthActionBuilder.SignInFailed(response));
        });
    }
    endSessionCallback() {
        this.internalEndSessionCallback().catch((response) => {
            this.notifyActionListers(AuthActionBuilder.SignOutFailed(response));
        });
    }
    getValidToken(buffer = AUTH_EXPIRY_BUFFER) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.session.token) {
                if (!this.session.token.isValid(buffer)) {
                    yield this.refreshToken();
                    if (this.session.token) {
                        return this.session.token;
                    }
                }
                else {
                    return this.session.token;
                }
            }
            throw new Error("Unable To Obtain Valid Token");
        });
    }
    addActionListener(func) {
        let observer = AuthObserver.Create(func);
        this.addActionObserver(observer);
        return observer;
    }
    addActionObserver(observer) {
        if (this._actionHistory.lastAction) {
            observer.update(this._actionHistory.lastAction);
        }
        this._authSubject.attach(observer);
    }
    removeActionObserver(observer) {
        this._authSubject.detach(observer);
    }
}
