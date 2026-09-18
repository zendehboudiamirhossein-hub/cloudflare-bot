require('dotenv').config();
const { Telegraf, Markup } = require('telegraf');
const fs = require('fs');
const path = require('path');
const http = require('http');
const store = require('./store');

const BOT_TOKEN = process.env.BOT_TOKEN;
if (!BOT_TOKEN) {
	console.error('BOT_TOKEN تنظیم نشده. آن را در Environment Variables ست کنید.');
	process.exit(1);
}

const WORKER_SOURCE = fs.readFileSync(path.join(__dirname, 'worker-src', 'panel.js'), 'utf8');
const CF_API = 'https://api.cloudflare.com/client/v4';
const TOKEN_URL =
	'https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=' +
	'%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C' +
	'%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C' +
	'%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C' +
	'%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%5D' +
	'&accountId=%2A&zoneId=all&name=Zeus%20Panel%20Deploy%20Token';

const bot = new Telegraf(BOT_TOKEN);

// session state per chat: { step, token, accountId, pendingAction }
// token/accountId are ONLY ever kept in this in-memory Map — never written to disk.
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

function mainMenu() {
	return Markup.inlineKeyboard([
		[Markup.button.callback('🚀 ساخت پنل جدید', 'connect_cf')],
		[Markup.button.callback('📋 پنل‌های من', 'my_panels')],
	]);
}

bot.start((ctx) => {
	sessions.set(ctx.chat.id, { step: 'idle' });
	ctx.reply(
		'سلام 👋\n' +
			'با این ربات می‌تونی پنل Zeus رو به‌صورت خودکار روی Cloudflare Workers دیپلوی، مدیریت و آپدیت کنی.\n\n' +
			'یکی از گزینه‌های زیر رو انتخاب کن:',
		mainMenu()
	);
});

bot.command('panels', (ctx) => sendPanelsList(ctx));

bot.action('connect_cf', async (ctx) => {
	await ctx.answerCbQuery();
	sessions.set(ctx.chat.id, { step: 'awaiting_token' });
	await ctx.reply(
		'روی دکمهٔ پایین بزن — صفحهٔ Cloudflare با تمام دسترسی‌های لازم از قبل پر شده باز می‌شه (Workers Scripts، KV، D1، Account Settings):\n\n' +
			'۱. پایین صفحه "Continue to summary" رو بزن\n' +
			'۲. "Create Token" رو بزن\n' +
			'۳. توکن رو کپی کن و همینجا برام بفرست 👇\n\n' +
			'⚠️ به‌دلیل امنیت خودِ Cloudflare، کلیک نهایی "Create Token" همیشه دست خودته — هیچ ربات یا سایتی نمی‌تونه جاش این کار رو بکنه.\n' +
			'توکن رو فقط برای همین دیپلوی استفاده می‌کنم و جایی ذخیرش نمی‌کنم.',
		Markup.inlineKeyboard([Markup.button.url('🔗 ساخت توکن با دسترسی‌های آماده', TOKEN_URL)])
	);
});

// ---------- پنل‌های من: لیست / جزئیات / آپدیت / حذف ----------

async function sendPanelsList(ctx) {
	const chatId = ctx.chat.id;
	const panels = store.listPanels(chatId);
	if (!panels.length) {
		await ctx.reply(
			'هنوز هیچ پنلی از طریق این ربات نساختی.',
			Markup.inlineKeyboard([Markup.button.callback('🚀 ساخت پنل جدید', 'connect_cf')])
		);
		return;
	}
	const buttons = panels.map((p) => [Markup.button.callback(`🌐 ${p.workerName}`, `panel_${p.workerName}`)]);
	buttons.push([Markup.button.callback('🚀 ساخت پنل جدید', 'connect_cf')]);
	await ctx.reply(`📋 پنل‌های ساخته‌شده (${panels.length} عدد):`, Markup.inlineKeyboard(buttons));
}

bot.action('my_panels', async (ctx) => {
	await ctx.answerCbQuery();
	await sendPanelsList(ctx);
});

bot.action(/^panel_(.+)$/, async (ctx) => {
	await ctx.answerCbQuery();
	const workerName = ctx.match[1];
	const panel = store.getPanel(ctx.chat.id, workerName);
	if (!panel) {
		await ctx.reply('این پنل پیدا نشد؛ شاید قبلاً حذف شده.');
		return;
	}
	const createdDate = new Date(panel.createdAt).toLocaleString('fa-IR');
	await ctx.reply(
		`🌐 پنل: ${panel.workerName}\n🔗 لینک: ${panel.panelUrl}\n📅 ساخته‌شده: ${createdDate}`,
		Markup.inlineKeyboard([
			[Markup.button.url('🔗 باز کردن پنل', panel.panelUrl)],
			[Markup.button.callback('🔄 آپدیت به آخرین نسخه', `update_${workerName}`)],
			[Markup.button.callback('🗑 حذف پنل', `delconfirm_${workerName}`)],
			[Markup.button.callback('◀️ بازگشت به لیست', 'my_panels')],
		])
	);
});

bot.action(/^update_(.+)$/, async (ctx) => {
	await ctx.answerCbQuery();
	const chatId = ctx.chat.id;
	const workerName = ctx.match[1];
	const panel = store.getPanel(chatId, workerName);
	if (!panel) {
		await ctx.reply('این پنل پیدا نشد.');
		return;
	}
	const session = getSession(chatId);
	if (session.token && session.accountId === panel.accountId) {
		await runUpdate(ctx, session.token, panel);
		return;
	}
	session.step = 'awaiting_token_manage';
	session.pendingAction = { type: 'update', workerName, accountId: panel.accountId };
	await ctx.reply(
		'برای آپدیت این پنل به توکن Cloudflare نیاز دارم (توکن قبلی توی حافظه نگه‌داری نمی‌شه). همون توکن قبلی یا یک توکن جدید با همون دسترسی‌ها رو بفرست:',
		Markup.inlineKeyboard([Markup.button.url('🔗 ساخت توکن', TOKEN_URL)])
	);
});

bot.action(/^delconfirm_(.+)$/, async (ctx) => {
	await ctx.answerCbQuery();
	const workerName = ctx.match[1];
	await ctx.reply(
		`⚠️ مطمئنی می‌خوای پنل «${workerName}» حذف بشه؟\n(فقط خودِ Worker حذف می‌شه؛ دیتابیس D1 مربوطه دست‌نخورده می‌مونه)`,
		Markup.inlineKeyboard([
			[Markup.button.callback('✅ بله، حذف کن', `delyes_${workerName}`)],
			[Markup.button.callback('❌ انصراف', `panel_${workerName}`)],
		])
	);
});

bot.action(/^delyes_(.+)$/, async (ctx) => {
	await ctx.answerCbQuery();
	const chatId = ctx.chat.id;
	const workerName = ctx.match[1];
	const panel = store.getPanel(chatId, workerName);
	if (!panel) {
		await ctx.reply('این پنل پیدا نشد.');
		return;
	}
	const session = getSession(chatId);
	if (session.token && session.accountId === panel.accountId) {
		await runDelete(ctx, session.token, panel);
		return;
	}
	session.step = 'awaiting_token_manage';
	session.pendingAction = { type: 'delete', workerName, accountId: panel.accountId };
	await ctx.reply(
		'برای حذف این پنل به توکن Cloudflare نیاز دارم. همون توکن قبلی یا یک توکن جدید با دسترسی Workers Scripts رو بفرست:',
		Markup.inlineKeyboard([Markup.button.url('🔗 ساخت توکن', TOKEN_URL)])
	);
});

async function runUpdate(ctx, token, panel) {
	await ctx.reply('⏳ در حال آپدیت پنل به آخرین نسخه...');
	try {
		await updatePanel(token, panel.accountId, panel.workerName);
		await ctx.reply('✅ پنل با موفقیت آپدیت شد (کاربران و دیتابیس دست‌نخورده باقی موندن).');
	} catch (err) {
		console.error(err);
		await ctx.reply('❌ آپدیت ناموفق بود: ' + err.message);
	}
}

async function runDelete(ctx, token, panel) {
	await ctx.reply('⏳ در حال حذف پنل...');
	try {
		await deleteWorker(token, panel.accountId, panel.workerName);
		store.removePanel(ctx.chat.id, panel.workerName);
		await ctx.reply('🗑 پنل حذف شد. (دیتابیس D1 حذف نشد؛ در صورت نیاز از داشبورد Cloudflare حذفش کن.)');
	} catch (err) {
		console.error(err);
		await ctx.reply('❌ حذف ناموفق بود: ' + err.message);
	}
}

// ---------- ورودی متنی: هم برای دیپلوی جدید، هم برای مدیریت پنل موجود ----------

bot.on('text', async (ctx) => {
	const chatId = ctx.chat.id;
	const session = getSession(chatId);
	const text = ctx.message.text.trim();

	if (session.step === 'awaiting_token') {
		await handleDeployToken(ctx, session, text);
	} else if (session.step === 'awaiting_token_manage') {
		await handleManageToken(ctx, session, text);
	}
});

async function handleDeployToken(ctx, session, text) {
	const chatId = ctx.chat.id;
	await ctx.reply('⏳ در حال بررسی توکن...');
	try {
		const accountId = await verifyTokenAndGetAccount(ctx, text);
		if (!accountId) return;

		session.token = text;
		session.accountId = accountId;
		session.step = 'deploying';

		await ctx.reply('✅ توکن تایید شد.\n⏳ در حال ساخت دیتابیس و دیپلوی پنل... (ممکنه یکی دو دقیقه طول بکشه)');
		const { workerName, panelUrl } = await deployPanel(session.token, accountId);

		store.addPanel(chatId, { workerName, accountId, panelUrl, createdAt: Date.now() });

		session.step = 'done';
		await ctx.reply(
			'🎉 پنل با موفقیت دیپلوی شد!\n\n' +
				`🔗 لینک پنل:\n${panelUrl}\n\n` +
				'در اولین ورود، رمز پنل رو خودت تنظیم می‌کنی.\n\n' +
				'⚠️ توکن Cloudflare‌ت رو جایی امن نگه‌دار و به کسی نده.\n\n' +
				'برای دیدن/آپدیت/حذف این پنل بعداً، از دکمهٔ «📋 پنل‌های من» استفاده کن.',
			mainMenu()
		);
	} catch (err) {
		console.error(err);
		await ctx.reply('❌ خطای غیرمنتظره: ' + err.message + '\nدوباره روی دکمه بزن و امتحان کن.');
		session.step = 'idle';
	}
}

async function handleManageToken(ctx, session, text) {
	const chatId = ctx.chat.id;
	const pending = session.pendingAction;
	if (!pending) {
		session.step = 'idle';
		return;
	}

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
		const hasAccess = accountsData.success && accountsData.result.some((a) => a.id === pending.accountId);
		if (!hasAccess) {
			await ctx.reply('❌ این توکن به اکانت Cloudflare‌ای که این پنل توشه دسترسی نداره.');
			return;
		}

		session.token = text;
		session.accountId = pending.accountId;
		session.step = 'idle';
		session.pendingAction = null;

		const panel = store.getPanel(chatId, pending.workerName) || {
			workerName: pending.workerName,
			accountId: pending.accountId,
		};

		if (pending.type === 'update') {
			await runUpdate(ctx, text, panel);
		} else if (pending.type === 'delete') {
			await runDelete(ctx, text, panel);
		}
	} catch (err) {
		console.error(err);
		await ctx.reply('❌ خطای غیرمنتظره: ' + err.message);
		session.step = 'idle';
		session.pendingAction = null;
	}
}

async function verifyTokenAndGetAccount(ctx, token) {
	const verifyRes = await fetch(`${CF_API}/user/tokens/verify`, { headers: cfHeaders(token, false) });
	const verifyData = await verifyRes.json();
	if (!verifyRes.ok || !verifyData.success) {
		await ctx.reply('❌ توکن نامعتبره یا منقضی شده. دوباره بساز و بفرست.');
		return null;
	}
	const accountsRes = await fetch(`${CF_API}/accounts`, { headers: cfHeaders(token, false) });
	const accountsData = await accountsRes.json();
	if (!accountsData.success || !accountsData.result.length) {
		await ctx.reply('❌ هیچ اکانت Cloudflare‌ای با این توکن پیدا نشد.');
		return null;
	}
	return accountsData.result[0].id;
}

// ---------- عملیات Cloudflare ----------

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
			{ type: 'secret_text', name: 'CF_API_TOKEN', text: token },
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

	const panelUrl = subdomain
		? `https://${workerName}.${subdomain}.workers.dev/panel`
		: `(دیپلوی شد اما subdomain گرفته نشد — از Cloudflare Dashboard → Workers & Pages → ${workerName} چک کن)`;

	return { workerName, panelUrl, databaseId };
}

// Re-uploads the current worker-src/panel.js to an EXISTING worker, keeping its
// D1 binding (and any other custom bindings) intact. CF_API_TOKEN/CF_ACCOUNT_ID/
// WORKER_NAME are always re-written fresh with the token used for this call,
// exactly like the panel's own internal self-update logic does.
async function updatePanel(token, accountId, workerName) {
	const settingsRes = await fetch(`${CF_API}/accounts/${accountId}/workers/scripts/${workerName}/settings`, {
		headers: cfHeaders(token, false),
	});
	const settingsData = await settingsRes.json();
	let bindings = [];
	if (settingsData.success && settingsData.result && Array.isArray(settingsData.result.bindings)) {
		bindings = settingsData.result.bindings.filter(
			(b) => b.name !== 'CF_API_TOKEN' && b.name !== 'CF_ACCOUNT_ID' && b.name !== 'WORKER_NAME'
		);
	}
	bindings.push({ type: 'plain_text', name: 'CF_ACCOUNT_ID', text: accountId });
	bindings.push({ type: 'secret_text', name: 'CF_API_TOKEN', text: token });
	bindings.push({ type: 'plain_text', name: 'WORKER_NAME', text: workerName });

	const metadata = {
		main_module: 'panel.js',
		compatibility_date: '2024-09-01',
		bindings,
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
	if (!uploadData.success) throw new Error(JSON.stringify(uploadData.errors));
}

async function deleteWorker(token, accountId, workerName) {
	const res = await fetch(`${CF_API}/accounts/${accountId}/workers/scripts/${workerName}`, {
		method: 'DELETE',
		headers: cfHeaders(token, false),
	});
	if (res.status === 404) return; // already gone, treat as success
	const data = await res.json().catch(() => ({}));
	if (!res.ok && !(data && data.success)) {
		throw new Error(JSON.stringify(data.errors || data));
	}
}

// Minimal HTTP server so Railway health checks pass (this service itself needs no public traffic)
const PORT = process.env.PORT || 3000;
http.createServer((req, res) => { res.writeHead(200); res.end('zeus-deploy-bot is running'); }).listen(PORT);

bot.launch();
console.log('Bot started.');
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
