import * as admin from "firebase-admin";
import * as functions from "firebase-functions";
import * as express from "express";
import { ProtectedResourceEndpointResponse } from "oauth2-nodejs";
import { AbstractProtectedResourceEndpoint } from "./abstract_protected_resource_endpoint";

export class UserinfoEndpoint extends AbstractProtectedResourceEndpoint {

  constructor(regions: string[]) {
    super(regions)
  }

  protected handleRequest(
    req: express.Request,
    endpointInfo: ProtectedResourceEndpointResponse
  ): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const auth = admin.auth();

      auth
        .getUser(endpointInfo.userId)
        .then((userRecord) => {
          resolve(
            JSON.stringify({
              sub: endpointInfo.userId,
              name: userRecord.displayName,
              email: userRecord.email,
              scopes: endpointInfo.scope.split(" ")
            })
          );
        })
        .catch((e) => {
          reject(e);
        });
    });
  }

  protected validateScope(scopes: string[]): boolean {
    return scopes.indexOf("profile") !== -1;
  }
}

export function userinfo(regions: string[]): functions.HttpsFunction {
  return new UserinfoEndpoint(regions).endpoint;
}
