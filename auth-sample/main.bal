import ballerina/http;
import ballerina/jwt;

import ballerina/time;

final string SECRET = "supersecretkey";

map<string> userStore = {
    "admin@example.com": "admin123",
    "user@example.com": "user123"
};

type LoginRequest record {
    string email;
    string password;
};

service /auth on new http:Listener(8080) {

    resource function post login(http:Request req) returns http:Response|error {
        json|error payload = req.getJsonPayload();
        if (payload is error) {
            http:Response res = new;
            res.statusCode = 400;
            res.setJsonPayload({ "error": "Invalid JSON" });
            return res;
        }

        LoginRequest|error loginReq = payload.cloneWithType(LoginRequest);
        if (loginReq is error) {
            http:Response res = new;
            res.statusCode = 400;
            res.setJsonPayload({ "error": "Invalid data format" });
            return res;
        }

        if userStore.hasKey(loginReq.email) && userStore[loginReq.email] == loginReq.password {
            decimal exp = <decimal>time:utcNow()[0] + 3600;

            jwt:IssuerConfig issuerConfig = {
                issuer: "auth-service",
                username: loginReq.email,
                expTime: exp,
                signatureConfig: {
    algorithm: jwt:HS256,
  config: SECRET
}

            };

            string|error token = jwt:issue(issuerConfig);
            if (token is string) {
                http:Response res = new;
                res.statusCode = 200;
                res.setJsonPayload({ "token": token });
                return res;
            } else {
                http:Response res = new;
                res.statusCode = 500;
                res.setJsonPayload({ "error": "Token generation failed" });
                return res;
            }
        } else {
            http:Response res = new;
            res.statusCode = 401;
            res.setJsonPayload({ "error": "Invalid credentials" });
            return res;
        }
    }

    resource function get secure(http:Request req) returns http:Response|error {
        string|error authHeader = req.getHeader("Authorization");
        if (authHeader is string && authHeader.startsWith("Bearer ")) {
            string jwtToken = authHeader.substring(7);

            jwt:ValidatorConfig validatorConfig = {
                issuer: "auth-service",
                clockSkew: 60,
                signatureConfig: {
                    secret: SECRET
                }
            };

            jwt:Payload|error verified = jwt:validate(jwtToken, validatorConfig);
            if (verified is jwt:Payload) {
                anydata? subjectValue = verified["sub"];
                string username = subjectValue is string ? subjectValue : "unknown";

                http:Response res = new;
                res.statusCode = 200;
                res.setJsonPayload({ "message": "Authorized!", "user": username });
                return res;
            }
        }
        http:Response res = new;
        res.statusCode = 401;
        res.setJsonPayload({ "error": "Unauthorized" });
        return res;
    }
}
