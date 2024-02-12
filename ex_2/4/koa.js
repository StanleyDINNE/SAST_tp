
const Koa = require('koa');
const urlLib = require('url');
const app = new Koa();

app.use(async ctx => {
	var url = ctx.query.target;
	ctx.redirect('http://example.com/' + url);
});

app.listen(3000);
