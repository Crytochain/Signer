mongoose = require( 'mongoose' );
var Schema   = mongoose.Schema;
var config = require('./config');
var userconfig = require('./userconfig');

mongoose.connect(process.env.MONGO_URI || 'mongodb://'+userconfig.mongoUserName.toString()+':'+userconfig.mongoPwd.toString()+'@' + userconfig.mongoHost.toString() + '/'+userconfig.dbname.toString());
mongoose.set('debug', false);
