# twitter-api-proxy

ウェブアプリケーションの Cookie を利用して Twitter API の OAuth 1.0a を再現するプロキシ

## 使用手順

### SSL/TLS 証明書を設定する

* 認証局証明書を作成する
* `api.twitter.com` の秘密鍵 `private.key` と CSR を作成する
* 認証局で署名した `api.twitter.com` の証明書 `api.twitter.com.crt` を作成する
* 認証局証明書をクライアントで信頼する

### 起動する

* HTTPS でアクセス可能なアドレス（例 `203.0.113.1`）で起動する

```
$ npm install
$ sudo npm start
```

### `api.twitter.com` の名前解決を変更する

* `api.twitter.com` を `203.0.113.1` に解決する

### クライアントからアクセスする

#### [Echofon](https://www.echofon.com/)

#### [Twitterrific](https://twitterrific.com/)
