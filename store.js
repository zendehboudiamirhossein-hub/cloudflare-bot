const fs = require('fs');
const path = require('path');

// NOTE: no Cloudflare token is ever stored here — only non-secret metadata
// needed to list/manage panels later (worker name, account id, panel url, date).
const DB_PATH = path.join(__dirname, 'data', 'panels.json');

function loadAll() {
	try {
		const raw = fs.readFileSync(DB_PATH, 'utf8');
		return JSON.parse(raw);
	} catch (err) {
		return {};
	}
}

function saveAll(data) {
	fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
	fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
}

function listPanels(chatId) {
	const data = loadAll();
	return data[String(chatId)] || [];
}

function getPanel(chatId, workerName) {
	return listPanels(chatId).find((p) => p.workerName === workerName) || null;
}

function addPanel(chatId, panel) {
	const data = loadAll();
	const key = String(chatId);
	if (!data[key]) data[key] = [];
	data[key].push(panel);
	saveAll(data);
}

function removePanel(chatId, workerName) {
	const data = loadAll();
	const key = String(chatId);
	if (!data[key]) return;
	data[key] = data[key].filter((p) => p.workerName !== workerName);
	saveAll(data);
}

module.exports = { listPanels, getPanel, addPanel, removePanel };

