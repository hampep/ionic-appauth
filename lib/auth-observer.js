import { AuthActions } from './auth-action';
import { Guid } from "guid-typescript";
import { DefaultAuthSession } from './auth-session';
export class BaseAuthObserver {
    constructor() {
        this.id = Guid.create();
    }
}
export class AuthObserver extends BaseAuthObserver {
    constructor(func) {
        super();
        this.func = func;
    }
    update(action) {
        this.func(action);
    }
    static Create(func) {
        return new AuthObserver(func);
    }
}
export class TokenObserver extends BaseAuthObserver {
    update(action) {
        this.token = action.tokenResponse;
    }
}
export class ActionHistoryObserver extends BaseAuthObserver {
    constructor() {
        super(...arguments);
        this.history = [];
    }
    update(action) {
        this.lastAction = action;
        this.history.push(action);
    }
}
export class SessionObserver extends BaseAuthObserver {
    constructor() {
        super(...arguments);
        this.session = new DefaultAuthSession();
    }
    update(action) {
        switch (action.action) {
            case AuthActions.SignInFailed:
            case AuthActions.RefreshFailed:
            case AuthActions.LoadTokenFromStorageFailed:
                this.session.error = action.error;
                this.session.token = undefined;
                this.session.user = undefined;
                this.session.isAuthenticated = false;
                break;
            case AuthActions.SignInSuccess:
            case AuthActions.RefreshSuccess:
            case AuthActions.LoadTokenFromStorageSuccess:
                this.session.error = undefined;
                this.session.token = action.tokenResponse;
                this.session.isAuthenticated = true;
                break;
            case AuthActions.LoadUserInfoSuccess:
                this.session.error = undefined;
                this.session.user = action.user;
                break;
            case AuthActions.LoadUserInfoFailed:
                this.session.error = action.error;
                this.session.user = undefined;
                break;
            case AuthActions.SignOutSuccess:
            case AuthActions.Default:
                this.session = new DefaultAuthSession();
                break;
            case AuthActions.SignOutFailed:
                this.session.error = action.error;
                break;
        }
    }
}
export class ConsoleLogObserver extends BaseAuthObserver {
    update(action) {
        console.log(action);
    }
}
