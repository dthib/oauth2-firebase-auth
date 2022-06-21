import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import * as express from "express";
import * as cors from "cors";
import * as path from "path";
import * as qs from "qs";

import { RequestWrapper } from "../models";
import { Configuration, Crypto, Navigation, processConsent } from "../utils";
import { CloudFirestoreClients } from "../data";

class AuthenticationApp {
  static create(
    providerName: string,
    authenticationUrl?: string
  ): express.Express {
    const authenticationApp = express();
    authenticationApp.use(cors({ origin: true }));

    authenticationApp.set("views", path.join(__dirname, "../../views"));

    authenticationApp.get("/", (req, resp) => {
      const request = new RequestWrapper(req);
      const authToken = request.getParameter("auth_token");

      const payload = {
        authToken: authToken,
      };

      if (authenticationUrl) {
        const strippedUrl = authenticationUrl.split("?")[0];
        const urlWithPayload = `${strippedUrl}?${qs.stringify(payload)}`;

        resp.redirect(urlWithPayload);
      } else {
        resp.render("authentication.ejs", {
          ...payload,
          projectId: process.env.GCLOUD_PROJECT,
          projectApiKey: Configuration.instance.project_apikey,
          providerName: providerName,
        });
      }
    });

    authenticationApp.post("/", async (req, resp) => {
      const request = new RequestWrapper(req);
      const encryptedAuthToken = request.getParameter("auth_token")!;
      const idTokenString = request.getParameter("id_token")!;
      const success = request.getParameter("success");
      const error = request.getParameter("error");

      const authToken = JSON.parse(
        Crypto.decrypt(request.getParameter("auth_token")!)
      );

      let client;

      if (success === "true") {
        try {
          const idToken = await admin.auth().verifyIdToken(idTokenString);

          if (idToken.aud === process.env.GCLOUD_PROJECT) {
            // Check for implicit consent
            client = await CloudFirestoreClients.fetch(authToken["client_id"]);

            // Call here to prevent unnecessary redirect to /consent
            if (client?.implicitConsent) {
              const payload = await processConsent(
                resp,
                {
                  action: "allow",
                  authToken,
                  userId: idToken.sub,
                },
                { redirect: !client?.browserRedirect }
              );

              // If we're here, then we're relying on browser to carry out redirect to prevent hitting CORS
              return resp.json(payload);
            } else {
              const encryptedUserId = Crypto.encrypt(idToken.sub);

              Navigation.redirect(resp, "/authorize/consent", {
                auth_token: encryptedAuthToken,
                user_id: encryptedUserId,
              });
            }
          }
        } catch (e) {
          console.log("e", e);
        }
      } else {
        console.log("error", error);
      }

      if (client?.browserRedirect) {
        return resp.json({
          error: "access_denied",
        });
      }

      Navigation.redirect(resp, authToken["redirect_uri"], {
        error: "access_denied",
      });

      return;
    });

    return authenticationApp;
  }
}

export function googleAccountAuthentication(regions: string[]) {
  return functions.region(...regions).https.onRequest(AuthenticationApp.create("Google"));
}

export function facebookAccountAuthentication(regions: string[]) {
  return functions.region(...regions).https.onRequest(AuthenticationApp.create("Facebook"));
}

export function githubAccountAuthentication(regions: string[]) {
  return functions.region(...regions).https.onRequest(AuthenticationApp.create("Github"));
}

export function customAuthentication(regions: string[], authenticationUrl: string) {
  return functions.region(...regions).https.onRequest(
    AuthenticationApp.create("Custom", authenticationUrl)
  );
}
