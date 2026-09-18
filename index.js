require('dotenv').config();
const { Telegraf, Markup } = require('telegraf');
const fs = require('fs');
const path = require('path');
const http = require('http');

const BOT_TOKEN = process.env.BOT_TOKEN;
if (!BOT_TOKEN) {
	console.error('BOT_TOKEN تنظیم نشده. آن را در Environment Variables ست کنید.');
	process.exit(1);
}

const WORKER_SOURCE = fs.readFileSync(path.join(__dirname, 'worker-src', 'panel.js'), 'utf8');
const CF_API = 'https://api.cloudflare.com/client/v4';

const bot = new Telegraf(BOT_TOKEN);

// session state per chat: { step, token, accountId }
const sessions = new Map();
function getSession(chatId) {
	if (!sessions.has(chatId)) sessions.set(chatId, { step: 'idle' });
	return sessions.get(chatId);
}

function cfHeaders(token, json = true) {
	const h = { Authorization: `Bearer ${token}` };
	if (json) h['Content-Type'] = 'application/json';
	return h;
}

bot.start((ctx) => {
	sessions.set(ctx.chat.id, { step: 'idle' });
	ctx.reply(
		'سلام 👋\n' +
		'با این ربات می‌تونی پنل Zeus رو به‌صورت خودکار روی Cloudflare Workers دیپلوی کنی.\n\n' +
		'برای شروع دکمه زیر رو بزن:',
		Markup.inlineKeyboard([Markup.button.callback('🔗 اتصال به Cloudflare و ساخت پنل', 'connect_cf')])
	);
});

bot.action('connect_cf', async (ctx) => {
	await ctx.answerCbQuery();
	sessions.set(ctx.chat.id, { step: 'awaiting_token' });
	await ctx.reply(
		'روی دکمهٔ پایین بزن تا مستقیم صفحهٔ ساخت توکن Cloudflare باز بشه:\n\n' +
		'۱. اونجا "Create Token" → تمپلیت آمادهٔ "Edit Cloudflare Workers" رو انتخاب کن (Use Template)\n' +
		'   این تمپلیت اکثر دسترسی‌های لازم رو از قبل داره (Workers Scripts، KV، Account Settings، User Details)\n' +
		'۲. فقط یک ردیف اضافه کن: Account → D1 → Edit\n' +
		'۳. "Continue to summary" بعد "Create Token" بزن\n' +
		'۴. توکن ساخته‌شده رو کپی کن و همینجا برام بفرست 👇\n\n' +
		'⚠️ به‌دلیل امنیت خودِ Cloudflare، هیچ ربات یا سایتی (حتی این ربات) نمی‌تونه به‌جای تو روی "Create Token" کلیک کنه — این تاییدیهٔ آخر همیشه دست خودته.\n' +
		'توکن رو فقط برای همین دیپلوی استفاده می‌کنم و جایی ذخیرش نمی‌کنم.',
		Markup.inlineKeyboard([Markup.button.url('🔗 باز کردن صفحهٔ ساخت توکن', 'https://dash.cloudflare.com/profile/api-tokens')])
	);
});

bot.on('text', async (ctx) => {
	const chatId = ctx.chat.id;
	const session = getSession(chatId);
	const text = ctx.message.text.trim();
	if (session.step !== 'awaiting_token') return;

	await ctx.reply('⏳ در حال بررسی توکن...');
	try {
		const verifyRes = await fetch(`${CF_API}/user/tokens/verify`, { headers: cfHeaders(text, false) });
		const verifyData = await verifyRes.json();
		if (!verifyRes.ok || !verifyData.success) {
			await ctx.reply('❌ توکن نامعتبره یا منقضی شده. دوباره بساز و بفرست.');
			return;
		}

		const accountsRes = await fetch(`${CF_API}/accounts`, { headers: cfHeaders(text, false) });
		const accountsData = await accountsRes.json();
		if (!accountsData.success || !accountsData.result.length) {
			await ctx.reply('❌ هیچ اکانت Cloudflare‌ای با این توکن پیدا نشد.');
			return;
		}
		const accountId = accountsData.result[0].id;
		session.token = text;
		session.accountId = accountId;
		session.step = 'deploying';

		await ctx.reply('✅ توکن تایید شد.\n⏳ در حال ساخت دیتابیس و دیپلوی پنل... (ممکنه یکی دو دقیقه طول بکشه)');
		const panelUrl = await deployPanel(session.token, accountId);

		session.step = 'done';
		await ctx.reply(
			'🎉 پنل با موفقیت دیپلوی شد!\n\n' +
			`🔗 لینک پنل:\n${panelUrl}\n\n` +
			'در اولین ورود، رمز پنل رو خودت تنظیم می‌کنی.\n\n' +
			'⚠️ توکن Cloudflare‌ت رو جایی امن نگه‌دار و به کسی نده.'
		);
	} catch (err) {
		console.error(err);
		await ctx.reply('❌ خطای غیرمنتظره: ' + err.message + '\nدوباره روی دکمه بزن و امتحان کن.');
		session.step = 'idle';
	}
});

async function deployPanel(token, accountId) {
	const workerName = 'zeus-panel-' + Math.random().toString(36).slice(2, 8);

	// 1. Create D1 database
	const dbRes = await fetch(`${CF_API}/accounts/${accountId}/d1/database`, {
		method: 'POST',
		headers: cfHeaders(token),
		body: JSON.stringify({ name: `${workerName}-db` }),
	});
	const dbData = await dbRes.json();
	if (!dbData.success) throw new Error('ساخت دیتابیس ناموفق بود: ' + JSON.stringify(dbData.errors));
	const databaseId = dbData.result.uuid;

	// 2. Upload worker script with bindings
	const metadata = {
		main_module: 'panel.js',
		compatibility_date: '2024-09-01',
		bindings: [
			{ type: 'd1', name: 'DB', id: databaseId },
			{ type: 'plain_text', name: 'CF_ACCOUNT_ID', text: accountId },
			{ type: 'plain_text', name: 'CF_API_TOKEN', text: token },
			{ type: 'plain_text', name: 'WORKER_NAME', text: workerName },
		],
	};

	const form = new FormData();
	form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
	form.append('panel.js', new Blob([WORKER_SOURCE], { type: 'application/javascript+module' }), 'panel.js');

	const uploadRes = await fetch(`${CF_API}/accounts/${accountId}/workers/scripts/${workerName}`, {
		method: 'PUT',
		headers: { Authorization: `Bearer ${token}` },
		body: form,
	});
	const uploadData = await uploadRes.json();
	if (!uploadData.success) throw new Error('آپلود پنل ناموفق بود: ' + JSON.stringify(uploadData.errors));

	// 3. Enable workers.dev subdomain for this script
	await fetch(`${CF_API}/accounts/${accountId}/workers/scripts/${workerName}/subdomain`, {
		method: 'POST',
		headers: cfHeaders(token),
		body: JSON.stringify({ enabled: true }),
	});

	// 4. Get account's workers.dev subdomain prefix
	const subRes = await fetch(`${CF_API}/accounts/${accountId}/workers/subdomain`, { headers: cfHeaders(token, false) });
	const subData = await subRes.json();
	const subdomain = subData.success ? subData.result.subdomain : null;

	if (!subdomain) {
		return `(دیپلوی شد اما subdomain گرفته نشد — از Cloudflare Dashboard → Workers & Pages → ${workerName} چک کن)`;
	}
	return `https://${workerName}.${subdomain}.workers.dev/panel`;
}

// Minimal HTTP server so Railway health checks pass (this service itself needs no public traffic)
const PORT = process.env.PORT || 3000;
http.createServer((req, res) => { res.writeHead(200); res.end('zeus-deploy-bot is running'); }).listen(PORT);

bot.launch();
console.log('Bot started.');
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
