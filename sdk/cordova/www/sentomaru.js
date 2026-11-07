// public entry of the Cordova plugin (window.Sentomaru). Fails closed at first use: where there is no native plugin (browser),
// cordova/exec rejects and the facade says ChannelError.
'use strict';
const exec = require('cordova/exec');
const { createSentomaru, fromExec, SentomaruError } = require('./bridge');

module.exports = createSentomaru(fromExec(exec));
module.exports.SentomaruError = SentomaruError;
