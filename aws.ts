import sha256 from "crypto-js/sha256";
import hmacSHA256 from "crypto-js/hmac-sha256";
import { getFormattedDate } from "./utils";

const createCanonicalHeaders = (headers) => {
  //
  const response = {};
  const canonicalHeaders = Object.keys(headers);
  for (const i of canonicalHeaders) {
    response[i.toLowerCase()] = headers[i].trim().replace(/\s+/g, " ");
  }
  return response;
};

const credentialsGetSigningKey = async (credentials, region, date, service) => {
  //
  let credsHash = await hmacSHA256(
    credentials.accessKeyId,
    credentials.secretKey
  );
  let key = `AWS4${credentials.secretKey}`;
  for (const i of [date, region, service, "aws4_request"]) {
    key = await hmacSHA256(i, key);
  }
  const signingKey = key; // returning as binary to add to hmac
  return signingKey;
};

const getSigningKey = async (credentials, region, date, service) => {
  //
  const key = credentialsGetSigningKey(credentials, region, date, service);
  return key;
};

const getCanonicalQuery = async (query) => {
  //
  const sortedQuery = Object.keys(query).sort();
  const canonicalQuery = sortedQuery
    .map((key) => {
      return `${key}=${query[key]}`;
    })
    .join("&");
  return canonicalQuery;
};

const getCanonicalPath = (path) => {
  //
  const canonicalPath = path;
  return canonicalPath;
};

const createCanonicalRequest = async (
  //
  request,
  canonicalHeaders,
  payloadHash
) => {
  const sortedHeaders = Object.keys(canonicalHeaders).sort();
  const canonicalPath = getCanonicalPath(request.path);
  const signedHeaders = sortedHeaders.join(";");
  const mappedHeaders = sortedHeaders
    .map((key) => {
      return `${key}:${canonicalHeaders[key]}`;
    })
    .join("\n");
  const canonicalQuery = await getCanonicalQuery(request.query);
  const canonicalRequest = `${request.method}\n${canonicalPath}\n${canonicalQuery}\n${mappedHeaders}\n\n${signedHeaders}\n${payloadHash}`;
  return canonicalRequest;
};

const createStringToSign = async (
  //
  amzDateTime,
  credentialScope,
  canonicalRequest
) => {
  //
  const hashedCanonicalRequest = await sha256(canonicalRequest);
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDateTime}\n${credentialScope}\n${hashedCanonicalRequest}`;
  return stringToSign;
};

export const getSignature = async (
  dateTime,
  scope,
  signingKey,
  canonicalRequest
) => {
  //
  const stringToSign = await createStringToSign(
    dateTime,
    scope,
    canonicalRequest
  );
  const signature = await hmacSHA256(stringToSign, await signingKey);
  const signatureString = signature.toString();
  return signatureString;
};

// Sign the request

export const sign = async (request, credentials, service) => {
  const payloadHash = await sha256(request.body).toString();
  const { date, time } = getFormattedDate();

  const scope = `${date}/${request.region}/${request.service}/aws4_request`;

  request.headers["x-amz-date"] = `${date}T${time}Z`;
  if (credentials.sessionToken) {
    request.headers["x-amz-security-token"] = credentials.sessionToken;
  }
  request.headers["x-amz-content-sha256"] = payloadHash;
  request.date = date;
  request.time = time;
  request.service = service;
  request.region = "us-east-2";

  const canonicalHeaders = createCanonicalHeaders(request.headers);

  const signingKey = await getSigningKey(
    credentials,
    request.region,
    request.date,
    request.service
  );

  const canonicalRequest = await createCanonicalRequest(
    request,
    canonicalHeaders,
    payloadHash
  );

  const signRequest = async (request) => {
    const canonicalHeaders = await createCanonicalHeaders(request.headers);
    const algorithm = "AWS4-HMAC-SHA256";
    const scope = `${request.date}/${request.region}/${request.service}/aws4_request`;
    const signedHeaders = Object.keys(canonicalHeaders).sort();
    const signature = await getSignature(
      `${request.date}T${request.time}Z`,
      `${request.date}/${request.region}/${request.service}/aws4_request`,
      signingKey,
      canonicalRequest
    );
    const authorizationHeader = `${algorithm} Credential=${
      credentials.accessKeyId
    }/${scope}, SignedHeaders=${signedHeaders.join(
      ";"
    )}, Signature=${signature}`;
    request.headers["authorization"] = authorizationHeader;
    return request;
  };

  const signedRequest = await signRequest(request);
  return signedRequest;
};

export async function dynamodbCommand(identity, command, params) {
  const targets = {
    PutItem: "DynamoDB_20120810.PutItem",
    GetItem: "DynamoDB_20120810.GetItem",
    UpdateItem: "DynamoDB_20120810.UpdateItem",
    DeleteItem: "DynamoDB_20120810.DeleteItem",
    Query: "DynamoDB_20120810.Query",
    Scan: "DynamoDB_20120810.Scan",
    BatchWriteItem: "DynamoDB_20120810.BatchWriteItem",
    BatchGetItem: "DynamoDB_20120810.BatchGetItem",
  };
  const request = {
    method: "POST",
    hostname: "dynamodb.us-east-2.amazonaws.com",
    path: "/",
    port: undefined,
    query: {},
    headers: {
      "content-type": "application/x-amz-json-1.0",
      "x-amz-target": targets[command],
      host: "dynamodb.us-east-2.amazonaws.com",
    },
    body: JSON.stringify(params),
  };

  const credentials = {
    accessKeyId: identity.Credentials.AccessKeyId,
    secretKey: identity.Credentials.SecretKey,
    sessionToken: identity.Credentials.SessionToken,
  };

  const signedRequest = await sign(request, credentials, "dynamodb");

  const url = `https://${request.hostname}${
    request.path
  }?${await getCanonicalQuery(request.query)}`;

  const requestOptions = {
    method: signedRequest.method,
    headers: new Headers(signedRequest.headers),
    body: signedRequest.body,
  };

  const fetchRequest = new Request(url, requestOptions);

  const res = await fetch(fetchRequest).then(async (r) => {
    const { status, statusText, headers } = r;
    const body = await r.json();
    return { status, statusText, headers, body };
  });
  return res;
}

export const lambdaInvoke = async (identity, url, method, payload) => {
  const request = {
    method: method,
    hostname: url.split("/")[2],
    path: "/",
    port: undefined,
    query: {},
    headers: {
      "content-type": "application/x-amz-json-1.0",
      host: url.split("/")[2],
    },
    body: JSON.stringify({
      Payload: JSON.stringify(payload),
    }),
  };

  const credentials = {
    accessKeyId: identity.Credentials.accessKeyId,
    secretKey: identity.Credentials.secretKey,
    sessionToken: identity.Credentials.sessionToken,
  };

  const signedRequest = await sign(request, credentials, "lambda");

  const requestOptions = {
    method: signedRequest.method,
    headers: new Headers(signedRequest.headers),
    body: signedRequest.body,
  };

  const fetchRequest = new Request(url, requestOptions);

  const res = await fetch(fetchRequest).then(async (r) => {
    const { status, statusText, headers } = r;
    let body;
    body = await r.json();
    return { status, statusText, headers, body };
  });
  console.log(res);
  return res;
};

