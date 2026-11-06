# GDTF Share API

## Introduction

GDTF Share provides a REST API that lets an application authenticate, view
fixture revisions, and download revisions without accessing the GDTF Share
website through a web browser.

## Changes to the documentation

Since the GDTF Share API description was originally released, this
documentation has been updated as follows:

- Improved wording, spelling, and examples
- Clarified recommended API usage
- Added general usage and attribution requirements

## Use cases

This API is intended for developers who want to integrate GDTF Share functionality into
their applications. Common use cases include:

- Applications that provide GDTF Share functionality without embedding a full web browser.
- Custom interfaces for logging in, listing revisions, or downloading files in consoles and other applications.
- Integration of the GDTF database into fixture type patching workflows.

## Usage of the API

### File server

We recommend that developers use the GDTF Share API to synchronize GDTF files
with a server they operate, then serve those files to their application through
their own API. The server authenticates with GDTF Share and handles
synchronization, so end users do not need to log in to GDTF Share individually.
This approach can reduce traffic to GDTF Share, limit the information it
receives about end users' IP addresses, geolocation, and usage, and reduce the
application's dependence on GDTF Share availability. Applications may also
connect directly to GDTF Share; in that case, each user must authenticate with
their own GDTF Share account.

### Caching

Temporary caching of GDTF files is permitted. Keep cached files up to date:
the cache must not be more than 24 hours old. To help avoid overloading GDTF
Share infrastructure, we recommend refreshing the cache approximately every
120 minutes.

### Listing and Search

When listing GDTF files, you must use the **uploader** field returned by the
[Get List](#get-list) function to identify and clearly label each file. This
allows users to distinguish files provided by manufacturers from files created
by users.

When providing search across GDTF files, you must search both the
[**Name**](developers/gdtf_1_2/file-format-definition/index.html#table-3-fixture-type-node-attributes)
and
[**LongName**](developers/gdtf_1_2/file-format-definition/index.html#table-3-fixture-type-node-attributes)
fields. Searching **LongName** as well as **Name** helps users find files whose
names contain special characters.

### Attribution

When using GDTF files in your application, you must provide attribution. Include
the credit “Powered by GDTF” in the product user manual, digital About screen,
or accompanying technical documentation, and display the GDTF logo alongside
the credit:

<img src="media/gdtf.svg" link="https://www.gdtf-share.com/" alt="GDTF & MVR Logo" caption="Powered by GDTF" height="130px" class="left" />

## Reporting GDTF Share API Issues

To report an issue with the GDTF Share API, use the
[contact form](https://gdtf-share.com/landing/pages/contactUs.php) and select
“Problems or Issues.”

## API functions

- [Login](#login): Authenticate with a GDTF Share username and password.
- [Get List](#get-list): Retrieve a list of revisions.
- [Download](#file-download): Download a file by its revision ID.

Each function is described in the [Functions](#functions) section.

## Requirements

### GDTF Share User Account

A GDTF Share account is required for each client that authenticates directly
with the API. If your application connects directly, each user must use their
own account. If your application gets files from your sync server, only the
server needs to authenticate with GDTF Share; end users do not need individual
GDTF Share accounts. Users who need an account can
[sign up for a free GDTF Share account](https://gdtf-share.com/landing/pages/signUp.html).

### Software

To use the API, you need an HTTP client, such as `curl`, available on many
operating systems and platforms. For an introduction to web APIs, see the
[MDN Web API documentation](https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Client-side_web_APIs/Introduction).

### Cookies

A session cookie is required to authenticate API requests. Include the cookie
with each subsequent request; requests without it will not be authenticated.
The cookie expires after two hours of inactivity, after which the account used
by the API client must log in again.

The sample requests show how to use a cookie file with `curl`. For more
information about cookies, see [MDN's guide to HTTP
cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies).

## Functions

### Login

Use this function to authenticate with a username and password.

<table>
    <tr>
        <th>Method</th>
        <th>Content type</th>
        <th>Path</th>
    </tr>
    <tr>
        <td>POST</td>
        <td>application/json</td>
        <td>https://gdtf-share.com/apis/public/login.php</td>
    </tr>
</table>

#### Parameters

<table>
    <tr>
        <th>Parameter</th>
        <th>Required/optional</th>
        <th>Description</th>
        <th>Type</th>
    </tr>
    <tr>
        <td>user</td>
        <td>Required</td>
        <td>Username registered with GDTF Share.</td>
        <td>URL Encoded String</td>
    </tr>
    <tr>
        <td>password</td>
        <td>Required</td>
        <td>Password for the user's account.</td>
        <td>URL Encoded String</td>
    </tr>
</table>

#### Response

<table>
    <tr>
        <th>Content type</th>
        <th>HTTP status codes</th>
    </tr>
    <tr>
        <td>application/json</td>
        <td>200, 400, 401</td>
    </tr>
</table>

#### Sample request

```bash
curl -c session.txt -L -X POST https://gdtf-share.com/apis/public/login.php \
        -H 'Content-Type: application/json' \
        -d '{"user":"<username>", "password":"<password>"}'
```

#### Sample response

**On success:** HTTP status code 200

```json
{ "result": true, "notice": "Welcome! Why did the coffee file a police report?  It got mugged." }
```

**On error:** HTTP status code 401

```json
{ "result": false, "error": "No valid user or password provided." }
```

### Get List

Use this function to retrieve the list of revisions.

<table>
    <tr>
        <th>Method</th>
        <th>Path</th>
    </tr>
    <tr>
        <td>GET</td>
        <td>https://gdtf-share.com/apis/public/getList.php</td>
    </tr>
</table>

#### Parameters

This function does not require any parameters.

#### Response

<table>
    <tr>
        <th>Content type</th>
        <th>HTTP status codes</th>
    </tr>
    <tr>
        <td>application/json</td>
        <td>200, 400, 401, 500</td>
    </tr>
</table>

#### Sample request

```bash
curl -b session.txt https://gdtf-share.com/apis/public/getList.php
```

#### Sample response

**On success:** HTTP status code 200

```json
{ "result": true, "list": [<array>] }
```

**On error:** HTTP status code 401

```json
{ "result": false, "error": "Unauthorized." }
```

The `list` property in the response is an array. Each array element has the following format:

```json
{
  "rid": 12345,
  "fixture": "Example Fixture",
  "manufacturer": "Example Manufacturer",
  "revision": "Example revision",
  "creationDate": "1570494396",
  "lastModified": "1570494396",
  "uploader": "Manuf.",
  "rating": "4.1",
  "version": "1.0",
  "creator": "Real User 42",
  "uuid": "AAAAAAAA-3545-4C7C-ACA2-AAAAAAAAAAAA",
  "filesize": 4809117,
  "modes": [
    { "name": "mode1", "dmxfootprint": 49 },
    { "name": "mode2", "dmxfootprint": 52 }
  ]
}
```

#### Response definitions

The following table describes the fields in each response item.

<table>
    <tr>
        <th>Response item</th>
        <th>Description</th>
        <th>Data type</th>
    </tr>
    <tr>
        <td>rid</td>
        <td>Revision ID.</td>
        <td>Integer</td>
    </tr>
    <tr>
        <td>fixture</td>
        <td>Fixture name.</td>
        <td>String</td>
    </tr>
    <tr>
        <td>manufacturer</td>
        <td>Manufacturer name.</td>
        <td>String</td>
    </tr>
    <tr>
        <td>revision</td>
        <td>Revision name.</td>
        <td>String</td>
    </tr>
    <tr>
        <td>creationDate</td>
        <td>Revision creation date, represented as a Unix timestamp.</td>
        <td>Long</td>
    </tr>
    <tr>
        <td>lastModified</td>
        <td>Date the revision was last modified, represented as a Unix timestamp.</td>
        <td>Long</td>
    </tr>
    <tr>
        <td>uploader</td>
        <td>Uploader type: <code>Manuf.</code> if uploaded by a manufacturer, or <code>User</code> if uploaded by a user.</td>
        <td>String</td>
    </tr>
    <tr>
        <td>rating</td>
        <td>Rating of the revision, from 0 to 5.</td>
        <td>Float</td>
    </tr>
    <tr>
        <td>version</td>
        <td>GDTF version of the revision.</td>
        <td>String</td>
    </tr>
    <tr>
        <td>creator</td>
        <td>Username of the user who originally uploaded the file.</td>
        <td>String</td>
    </tr>
    <tr>
        <td>uuid</td>
        <td>Unique identifier for the fixture type. The identifier remains the same across revisions of that fixture.</td>
        <td>String</td>
    </tr>
    <tr>
        <td>filesize</td>
        <td>File size in bytes.</td>
        <td>Long</td>
    </tr>
    <tr>
        <td>modes</td>
        <td>Array of modes. Each item contains the mode name and its DMX footprint.</td>
        <td>Array</td>
    </tr>
</table>

Each entry in the modes array contains the following items:

<table>
    <tr>
        <th>Item</th>
        <th>Description</th>
        <th>Data type</th>
    </tr>
    <tr>
        <td>name</td>
        <td>Mode name.</td>
        <td>String</td>
    </tr>
    <tr>
        <td>dmxfootprint</td>
        <td>DMX footprint of the mode.</td>
        <td>Integer</td>
    </tr>
</table>

### File download

Use this function to download a single file.

<table>
    <tr>
        <th>Method</th>
        <th>Path</th>
    </tr>
    <tr>
        <td>GET</td>
        <td>https://gdtf-share.com/apis/public/downloadFile.php</td>
    </tr>
</table>

#### Parameters

<table>
    <tr>
        <th>Parameter</th>
        <th>Required/optional</th>
        <th>Description</th>
        <th>Type</th>
    </tr>
    <tr>
        <td>rid</td>
        <td>Required</td>
        <td>Revision ID returned by the Get List function.</td>
        <td>Integer</td>
    </tr>
</table>

#### Response

On success, the response contains the file as a binary stream. On error, the
response contains a JSON object with an error message. Use the HTTP status code
to determine whether the download succeeded.

<table>
    <tr>
        <th>Content type</th>
        <th>HTTP status codes</th>
    </tr>
    <tr>
        <td>application/octet-stream or application/json</td>
        <td>200, 400, 401, 404, 500</td>
    </tr>
</table>

#### Sample request

```bash
curl -b session.txt "https://gdtf-share.com/apis/public/downloadFile.php?rid=12345" \
    --output file.gdtf
```

#### Sample response

**On success:** HTTP status code 200

The file is saved as `file.gdtf`.

**On error:** HTTP status code 404

```json
{ "result": false, "error": "File does not exist." }
```
