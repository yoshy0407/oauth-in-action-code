var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information


/*
 * Add the client information in here
 */
var client = {
	"client_id": "",
	"client_secret": "",
	"redirect_uris": ["http://localhost:9000/callback"]
};

var protectedResource = 'http://localhost:9002/resource';

//ランダムなトークン文字列
var state = randomstring.generate();

var access_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope});
});

app.get('/authorize', function(req, res){
	/**
	 * 認可トークンの取得処理
	 * 必要なぱらめーたを設定して、
	 * 認可サーバの認可エンドポイントにリダイレクトするように設定して、クライアントに返却する
	 */	
	// リダイレクトURLを作成
	// stateはセキュリティ対策
	// アクセストークン取得エンドポイントが呼び出されるときに検証して、
	// トークンが一致しない場合にエラーとすることで、認証サーバを使用した攻撃を防ぐ
	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state
	})
	
	res.redirect(authorizeUrl)
});

app.get('/callback', function(req, res){
	/**
	 * 認可サーバから返ってきて、リダイレクトされて認可コードを受け取り、
	 * 認可サーバからアクセストークンを取得するエンドポイント
	 */

	// 事前に送っていたステータスの確認
	if (req.query.state != state) {
		res.render('error', { error: 'State value did not match' });
	}

	// 認可コード
	var code = req.query.code

	//アクセストークン取得エンドポイントの送信データを作成
	var form_data = qs.stringify({
		grant_type: 'authorization_code',
		code: code,
		redirect_uri: client.redirect_uris[0]
	})

	//アクセストークンエンドポイントでは、クライアント側となるシステムの認証も行われるべき
	var header = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	}

	// アクセストークンエンドポイントへPost
	var tokenRes = request('POST', authServer.tokenEndpoint,
		{
			body: form_data,
			headers: header
		});
	
	//レスポンスのボディのパース
	var body = JSON.parse(tokenRes.getBody());
	
	// アクセストークンを保管
	access_token = body.access_token;

	//画面表示
	res.render('index', { access_token: body.access_token, scope: scope })
	
});

app.get('/fetch_resource', function(req, res) {
	/*
	 * アクセストークンを使ってアクセスする
	 */
	// アクセストークンのチェック
	if (!access_token) {
		res.render('error', { error: 'Missing access token' })
	}

	//アクセストークンをリクエストヘッダーに設定
	var header = {
		'Authorization': 'Bearer ' + access_token
	}

	var response = request('POST', protectedResource, { headers: header });

	if (response.statusCode >= 200 && response.statusCode < 300) {
		var body = JSON.parse(response.getBody());

		res.render('data', { resource: body })
		return;
	} else {
		res.render('error', { error: 'Server returned response code: ' + response.statusCode });
		return;
	}
});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var encodeClientCredentials = function(clientId, clientSecret) {
	return Buffer.from(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
