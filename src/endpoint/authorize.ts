import * as functions from "firebase-functions";
import * as express from "express";
import * as ejs from "ejs";
import { RequestWrapper } from "../models";
import { AuthorizationEndpoint } from "oauth2-nodejs";
import {
  CloudFirestoreDataHandlerFactory,
  CloudFirestoreScopes,
  CloudFirestoreClients,
} from "../data";
import { Configuration, Crypto, Navigation, processConsent } from "../utils";

const authorizeApp = express();

authorizeApp.get("/entry", async (req, resp) => {
  const request = new RequestWrapper(req);
  const authorizationEndpoint = new AuthorizationEndpoint();

  authorizationEndpoint.dataHandlerFactory = new CloudFirestoreDataHandlerFactory();
  authorizationEndpoint.allowedResponseTypes = ["code", "token"];

  try {
    const authorizationEndpointResponse = await authorizationEndpoint.handleRequest(
      request
    );

    if (authorizationEndpointResponse.isSuccess()) {
      const authToken: { [key: string]: string | number } = {
        client_id: request.getParameter("client_id")!,
        redirect_uri: request.getParameter("redirect_uri")!,
        response_type: request.getParameter("response_type")!,
        scope: request.getParameter("scope")!,
        created_at: Date.now(),
      };

      const state = request.getParameter("state");

      if (state) {
        authToken["state"] = state;
      }

      const authTokenString = Crypto.encrypt(JSON.stringify(authToken));

      Navigation.redirect(resp, "/authentication/", {
        auth_token: authTokenString,
      });
    } else {
      const error = authorizationEndpointResponse.error;

      resp.set("Content-Type", "application/json; charset=UTF-8");
      resp.status(error.code).send(error.toJson());
    }
  } catch (e) {
    console.error(e);

    resp.status(500).send(e.toString());
  }
});

authorizeApp.get("/consent", async (req, resp) => {
  const request = new RequestWrapper(req);
  const encryptedAuthToken = request.getParameter("auth_token")!;
  const authToken = JSON.parse(Crypto.decrypt(encryptedAuthToken));
  const client = await CloudFirestoreClients.fetch(authToken["client_id"]);
  const encryptedUserId = request.getParameter("user_id")!;
  const scopes = await CloudFirestoreScopes.fetch();
  const consentViewTemplate = Configuration.instance.view_consent_template;

  try {
    const template = await consentViewTemplate.provide();
    const html = ejs.render(template, {
      scope: authToken["scope"],
      encryptedAuthToken,
      encryptedUserId,
      scopes,
      providerName: client!["providerName"],
    });

    resp.status(200).send(html);
  } catch (e) {
    console.error(e);
    resp.status(500).send(e.toString());
  }
});

authorizeApp.post("/consent", async (req, resp) => {
  const requestWrapper = new RequestWrapper(req);
  const encryptedAuthToken = requestWrapper.getParameter("auth_token")!;
  const authToken = JSON.parse(Crypto.decrypt(encryptedAuthToken));
  const encryptedUserId = requestWrapper.getParameter("user_id")!;
  const userId = Crypto.decrypt(encryptedUserId);
  const action = requestWrapper.getParameter("action");

  return processConsent(resp, {
    action,
    authToken,
    userId,
  });
});

export function authorize(regions: string[]) {
  return functions.region(...regions).https.onRequest(authorizeApp);
}
