# ScaleFT Audit Events app

This app will collect audit events from the [ScaleFT](https://www.scaleft.com) API and index them into Splunk. This makes tracking events like permission changes, server logins, credential approvals through ScaleFT simple.

You can help make this app better by contributing at [Github](https://www.github.com/ScaleFT/sft-audit-events-splunk).

# Getting Started

### Prerequisites
This modular input uses and requires NodeJS versions 4.0.0 or greater. Please visit the official [NodeJS website](https://nodejs.org/en/download/) for instructions on how to download and install NodeJS.

### New Install
1. Create a new service user in the [ScaleFT webapp](https://app.scaleft.com).
2. Create an API key for the new service user. Be sure to take note of the client id and client secret for your new API key.
3. Add your service user to a group, and be sure it has at least the 'Reporting' permission.
4. Install via the Splunk webapp (recommended) or copy the sft-audit-events-splunk app directory into `$SPLUNK_HOME/etc/apps/` location.
5. Restart the Splunk server.
6. Go to the Splunk "Data Input" settings, and create a new "ScaleFT Audit Event Input" local input.
7. Be sure to configure your new input correctly:
    * `name`: The name of the new input source. _sft_ is a sane choice.
    * `team_name`: The name of the team you'd like to receive events for.
    * `instance_address`: The address for ScaleFT. This should be `https://app.scaleft.com/` if you aren't running your own instance.
    * `polling_interval`: How often events should be imported in seconds. Defaults to 60 seconds.
    * `client_key`: The key id for your API key.
    * `client_secret`: The secret key for your API key.
    * `checkpoint_dir`: The directory to store any checkpoint data for the app. This can be anything, but `$SPLUNK_DB/modinputs/` will let splunk manage the data.
8. Enjoy!

### Dependencies
This modular input depends on a couple of npm modules:
  1. [request](https://www.npmjs.com/package/request) - [Apache 2.0](http://spdx.org/licenses/Apache-2.0)
  2. [async](https://www.npmjs.com/package/async) - [MIT](http://spdx.org/licenses/MIT)
  3. [splunk-sdk](https://www.npmjs.com/package/splunk-sdk) - [Apache 2.0](http://spdx.org/licenses/Apache-2.0)

# Whats New

### 1.0.5
 - Fix bug that caused the most recent audit event to be duplicated in splunk
 - Fix bug where service_token would not be refreshed for 10 hours, despite expiring after 1 hour

### 1.0.4
 - Set minimum required version of Node.js to v4.0.0
 - Vendored Node.js dependencies.

### 1.0.3
 - Bumped splunk-sdk to v1.8.1

### 1.0.2
 - Fixed input validation.
 - Added dependencies to README.

### 1.0.1
 - Fixed packaging issue.

### 1.0.0
 - Initial version of the app. Supports grabbing audit events from the ScaleFT using a service user.