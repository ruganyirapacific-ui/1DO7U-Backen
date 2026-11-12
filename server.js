'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

// ==========================================
// CONFIGURATION GÉNÉRALE
// ==========================================

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');

const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD || 'DO7U-ChangeThis-Password-2026';

const sessions = new Map();

fs.mkdirSync(DATA_DIR, { recursive: true });

// ==========================================
// INITIALISATION DE LA BASE DE DONNÉES
// ==========================================

if (!fs.existsSync(DB_FILE)) {

    const legacyDB = path.join(ROOT, 'db.json');

    if (legacyDB !== DB_FILE && fs.existsSync(legacyDB)) {

        fs.copyFileSync(legacyDB, DB_FILE);

    } else {

        fs.writeFileSync(
            DB_FILE,
            JSON.stringify({
                members: [],
                contributions: [],
                announcements: [],
                meetings: [],
                discussions: [],
                reactions: [],
                comments: [],
                attendance: []
            }, null, 2)
        );
    }
}

// ==========================================
// GESTION DE LA BASE DE DONNÉES
// ==========================================

function readDB() {

    try {

        const db = JSON.parse(
            fs.readFileSync(DB_FILE, 'utf8')
        );

        for (const key of [
            'members',
            'contributions',
            'announcements',
            'meetings',
            'discussions',
            'reactions',
            'comments',
            'attendance'
        ]) {

            if (!Array.isArray(db[key])) {
                db[key] = [];
            }
        }

        return db;

    } catch (error) {

        console.error('Erreur lecture DB :', error);

        return {
            members: [],
            contributions: [],
            announcements: [],
            meetings: [],
            discussions: [],
            reactions: [],
            comments: [],
            attendance: []
        };
    }
}

function writeDB(db) {

    const tmp = DB_FILE + '.tmp';

    fs.writeFileSync(
        tmp,
        JSON.stringify(db, null, 2)
    );

    fs.renameSync(tmp, DB_FILE);
}

// ==========================================
// OUTILS
// ==========================================

function id() {
    return crypto.randomBytes(10).toString('hex');
}

function clean(value, max = 1000) {
    return String(value ?? '').trim().slice(0, max);
}

function validMonth(value) {
    return /^\d{4}-(0[1-9]|1[0-2])$/.test(
        String(value || '')
    );
}

function hashPin(pin, salt) {

    const s = salt || crypto.randomBytes(16).toString('hex');

    return {
        salt: s,
        hash: crypto.scryptSync(
            String(pin),
            s,
            64
        ).toString('hex')
    };
}

function safeEqual(a, b) {

    const x = Buffer.from(String(a));
    const y = Buffer.from(String(b));

    return x.length === y.length &&
        crypto.timingSafeEqual(x, y);
}

// ==========================================
// GESTION DES COOKIES
// ==========================================

function cookies(req) {

    const out = {};

    (req.headers.cookie || '').split(';').forEach(part => {

        const i = part.indexOf('=');

        if (i > 0) {

            try {

                out[part.slice(0, i).trim()] =
                    decodeURIComponent(
                        part.slice(i + 1).trim()
                    );

            } catch {
                // Ignore les cookies mal formés.
            }
        }
    });

    return out;
}

function cookieSettings(req) {

    const isSecure =
        req.headers['x-forwarded-proto'] === 'https' ||
        process.env.NODE_ENV === 'production';

    return isSecure
        ? 'HttpOnly; SameSite=None; Secure; Path=/; Max-Age=28800'
        : 'HttpOnly; SameSite=Lax; Path=/; Max-Age=28800';
}

function clearCookieSettings(req) {

    const isSecure =
        req.headers['x-forwarded-proto'] === 'https' ||
        process.env.NODE_ENV === 'production';

    return isSecure
        ? 'HttpOnly; SameSite=None; Secure; Path=/; Max-Age=0'
        : 'HttpOnly; SameSite=Lax; Path=/; Max-Age=0';
}

// ==========================================
// RÉPONSES HTTP
// ==========================================

function send(
    res,
    status,
    data,
    type = 'application/json; charset=utf-8'
) {

    const body = type.startsWith('application/json')
        ? JSON.stringify(data)
        : data;

    res.writeHead(status, {
        'Content-Type': type,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Length': Buffer.byteLength(body)
    });

    res.end(body);
}

function bodyJSON(req) {

    return new Promise((resolve, reject) => {

        let raw = '';
        let size = 0;

        req.on('data', chunk => {

            size += chunk.length;

            if (size > 1_000_000) {

                reject(new Error('Requête trop volumineuse'));
                req.destroy();

            } else {

                raw += chunk;
            }
        });

        req.on('end', () => {

            try {

                resolve(raw ? JSON.parse(raw) : {});

            } catch {

                reject(new Error('JSON invalide'));
            }
        });

        req.on('error', reject);
    });
}

// ==========================================
// AUTHENTIFICATION
// ==========================================

function adminOK(req) {

    const token = cookies(req).do7u_admin;

    return !!token &&
        sessions.get(token) === 'admin';
}

function memberOK(req) {

    const token = cookies(req).do7u_member;

    const memberId = token && sessions.get(token);

    if (!memberId) return null;

    const member = readDB().members.find(
        x => x.id === memberId && x.active
    );

    return member || null;
}

function memberPublic(member) {

    return {
        id: member.id,
        code: member.code,
        name: member.name,
        active: member.active,
        createdAt: member.createdAt
    };
}

function unauthorized(res) {

    send(res, 401, {
        error: 'Veuillez vous connecter.'
    });
}

function forbidden(res) {

    send(res, 403, {
        error: 'Action réservée à l’administration.'
    });
}

// ==========================================
// API DO7U
// ==========================================

async function api(req, res, url) {

    const p = url.pathname;
    const method = req.method;

    // --------------------------------------
    // TEST DU BACKEND
    // --------------------------------------

    if (p === '/api/health' && method === 'GET') {

        return send(res, 200, {
            ok: true,
            app: 'DO7U'
        });
    }

    // --------------------------------------
    // DONNÉES PUBLIQUES
    // --------------------------------------

    if (p === '/api/public' && method === 'GET') {

        const db = readDB();

        return send(res, 200, {

            announcements: db.announcements
                .filter(x => x.published)
                .sort((a, b) =>
                    b.createdAt.localeCompare(a.createdAt)
                )
                .slice(0, 6),

            meetings: db.meetings
                .filter(x => x.published)
                .sort((a, b) =>
                    a.date.localeCompare(b.date)
                )
                .slice(0, 5),

            stats: {
                members: db.members.filter(x => x.active).length,
                activities: db.announcements.length,
                meetings: db.meetings.filter(x => x.published).length
            }
        });
    }

    // ======================================
    // CONNEXION ADMINISTRATEUR
    // ======================================

    if (p === '/api/admin/login' && method === 'POST') {

        const b = await bodyJSON(req);

        if (
            !safeEqual(clean(b.username, 80), ADMIN_USER) ||
            !safeEqual(String(b.password || ''), ADMIN_PASSWORD)
        ) {

            return send(res, 401, {
                error: 'Identifiants incorrects.'
            });
        }

        const token = crypto.randomBytes(32).toString('hex');

        sessions.set(token, 'admin');

        res.setHeader(
            'Set-Cookie',
            `do7u_admin=${token}; ${cookieSettings(req)}`
        );

        return send(res, 200, {
            ok: true
        });
    }

    if (p === '/api/admin/logout' && method === 'POST') {

        const token = cookies(req).do7u_admin;

        if (token) sessions.delete(token);

        res.setHeader(
            'Set-Cookie',
            `do7u_admin=; ${clearCookieSettings(req)}`
        );

        return send(res, 200, {
            ok: true
        });
    }

    if (p === '/api/admin/check' && method === 'GET') {

        return send(res, 200, {
            authenticated: adminOK(req)
        });
    }

    // ======================================
    // CONNEXION MEMBRE
    // ======================================

    if (p === '/api/member/login' && method === 'POST') {

        const b = await bodyJSON(req);

        const code = clean(b.code, 30).toUpperCase();
        const pin = String(b.pin || '');

        const db = readDB();

        const member = db.members.find(
            x => x.code === code && x.active
        );

        if (!member || !member.pinHash) {

            return send(res, 401, {
                error: 'Code membre ou PIN incorrect.'
            });
        }

        const attempt = hashPin(
            pin,
            member.pinSalt
        ).hash;

        if (!safeEqual(attempt, member.pinHash)) {

            return send(res, 401, {
                error: 'Code membre ou PIN incorrect.'
            });
        }

        const token = crypto.randomBytes(32).toString('hex');

        sessions.set(token, member.id);

        res.setHeader(
            'Set-Cookie',
            `do7u_member=${token}; ${cookieSettings(req)}`
        );

        return send(res, 200, {
            ok: true,
            member: memberPublic(member)
        });
    }

    if (p === '/api/member/logout' && method === 'POST') {

        const token = cookies(req).do7u_member;

        if (token) sessions.delete(token);

        res.setHeader(
            'Set-Cookie',
            `do7u_member=; ${clearCookieSettings(req)}`
        );

        return send(res, 200, {
            ok: true
        });
    }

    // ======================================
    // ESPACE MEMBRE
    // ======================================

    if (p === '/api/member/me' && method === 'GET') {

        const member = memberOK(req);

        if (!member) return unauthorized(res);

        const db = readDB();

        return send(res, 200, {

            member: memberPublic(member),

            contributions: db.contributions
                .filter(x => x.memberId === member.id)
                .sort((a, b) =>
                    b.month.localeCompare(a.month)
                ),

            announcements: db.announcements
                .filter(x => x.published)
                .sort((a, b) =>
                    b.createdAt.localeCompare(a.createdAt)
                )
                .map(a => ({
                    ...a,

                    reactionCount: db.reactions.filter(
                        r => r.announcementId === a.id
                    ).length,

                    likedByMe: db.reactions.some(
                        r =>
                            r.announcementId === a.id &&
                            r.memberId === member.id
                    ),

                    comments: db.comments.filter(
                        c => c.announcementId === a.id
                    )
                })),

            meetings: db.meetings
                .filter(x => x.published)
                .sort((a, b) =>
                    a.date.localeCompare(b.date)
                ),

            discussions: db.discussions
                .filter(x => x.published !== false)
                .sort((a, b) =>
                    b.createdAt.localeCompare(a.createdAt)
                ),

            attendance: db.attendance.filter(
                x => x.memberId === member.id
            )
        });
    }

    // ======================================
    // ROUTES ADMINISTRATEUR
    // ======================================

    if (p.startsWith('/api/admin/')) {

        if (!adminOK(req)) return forbidden(res);

        const db = readDB();

        // Tableau de bord

        if (p === '/api/admin/overview' && method === 'GET') {

            return send(res, 200, {

                members: db.members.filter(x => x.active).length,

                paidThisMonth: db.contributions.filter(
                    x => x.month === new Date().toISOString().slice(0, 7)
                ).length,

                announcements: db.announcements.length,

                meetings: db.meetings.filter(x => x.published).length
            });
        }

        // Gestion des membres

        if (p === '/api/admin/members' && method === 'GET') {

            return send(res, 200, {
                members: db.members.map(memberPublic)
            });
        }

        if (p === '/api/admin/members' && method === 'POST') {

            const b = await bodyJSON(req);

            const name = clean(b.name, 100);
            const pin = String(b.pin || '');

            if (name.length < 2) {

                return send(res, 400, {
                    error: 'Le nom complet est obligatoire.'
                });
            }

            if (!/^\d{4,8}$/.test(pin)) {

                return send(res, 400, {
                    error: 'Le PIN doit contenir 4 à 8 chiffres.'
                });
            }

            let code;

            do {

                code = 'DO7U-' +
                    crypto.randomBytes(3).toString('hex').toUpperCase();

            } while (db.members.some(x => x.code === code));

            const sec = hashPin(pin);

            const member = {
                id: id(),
                code,
                name,
                pinSalt: sec.salt,
                pinHash: sec.hash,
                active: true,
                createdAt: new Date().toISOString()
            };

            db.members.push(member);

            writeDB(db);

            return send(res, 201, {
                member: memberPublic(member)
            });
        }

        const memberMatch = p.match(
            /^\/api\/admin\/members\/([^/]+)$/
        );

        if (memberMatch && method === 'PATCH') {

            const member = db.members.find(
                x => x.id === memberMatch[1]
            );

            if (!member) {

                return send(res, 404, {
                    error: 'Membre introuvable.'
                });
            }

            const b = await bodyJSON(req);

            if (b.name !== undefined) {
                member.name = clean(b.name, 100);
            }

            if (b.active !== undefined) {
                member.active = !!b.active;
            }

            if (b.pin) {

                if (!/^\d{4,8}$/.test(String(b.pin))) {

                    return send(res, 400, {
                        error: 'PIN invalide.'
                    });
                }

                const s = hashPin(String(b.pin));

                member.pinSalt = s.salt;
                member.pinHash = s.hash;
            }

            writeDB(db);

            return send(res, 200, {
                member: memberPublic(member)
            });
        }

        // Cotisations

        if (p === '/api/admin/contributions' && method === 'GET') {

            const month = url.searchParams.get('month');

            if (!validMonth(month)) {

                return send(res, 400, {
                    error: 'Mois invalide.'
                });
            }

            return send(res, 200, {

                rows: db.members
                    .filter(m => m.active)
                    .map(m => ({

                        member: memberPublic(m),

                        payment: db.contributions.find(
                            c =>
                                c.memberId === m.id &&
                                c.month === month
                        ) || null
                    }))
            });
        }

        if (p === '/api/admin/contributions' && method === 'POST') {

            const b = await bodyJSON(req);

            const amount = Number(b.amount);
            const month = clean(b.month, 7);

            if (
                !validMonth(month) ||
                !Number.isFinite(amount) ||
                amount <= 0
            ) {

                return send(res, 400, {
                    error: 'Mois ou montant invalide.'
                });
            }

            const member = db.members.find(
                x => x.id === b.memberId && x.active
            );

            if (!member) {

                return send(res, 404, {
                    error: 'Membre actif introuvable.'
                });
            }

            let contribution = db.contributions.find(
                x =>
                    x.memberId === member.id &&
                    x.month === month
            );

            if (contribution) {

                contribution.amount = amount;
                contribution.note = clean(b.note, 300);
                contribution.paidAt = new Date().toISOString();
                contribution.status = 'paid';

            } else {

                contribution = {
                    id: id(),
                    memberId: member.id,
                    memberName: member.name,
                    month,
                    amount,
                    note: clean(b.note, 300),
                    paidAt: new Date().toISOString(),
                    status: 'paid'
                };

                db.contributions.push(contribution);
            }

            writeDB(db);

            return send(res, 200, {
                contribution
            });
        }

        // Annonces

        if (p === '/api/admin/announcements' && method === 'GET') {

            return send(res, 200, {
                announcements: db.announcements
            });
        }

        if (p === '/api/admin/announcements' && method === 'POST') {

            const b = await bodyJSON(req);

            const title = clean(b.title, 160);
            const text = clean(b.text, 4000);

            if (!title || !text) {

                return send(res, 400, {
                    error: 'Titre et contenu requis.'
                });
            }

            const announcement = {
                id: id(),
                title,
                text,
                type: clean(b.type, 40) || 'Annonce',
                published: true,
                createdAt: new Date().toISOString()
            };

            db.announcements.push(announcement);

            writeDB(db);

            return send(res, 201, {
                announcement
            });
        }

        const annMatch = p.match(
            /^\/api\/admin\/announcements\/([^/]+)$/
        );

        if (annMatch && method === 'PATCH') {

            const announcement = db.announcements.find(
                x => x.id === annMatch[1]
            );

            if (!announcement) {

                return send(res, 404, {
                    error: 'Publication introuvable.'
                });
            }

            const b = await bodyJSON(req);

            if (b.title !== undefined) {
                announcement.title = clean(b.title, 160);
            }

            if (b.text !== undefined) {
                announcement.text = clean(b.text, 4000);
            }

            if (b.published !== undefined) {
                announcement.published = !!b.published;
            }

            writeDB(db);

            return send(res, 200, {
                announcement
            });
        }

        // Réunions

        if (p === '/api/admin/meetings' && method === 'GET') {

            return send(res, 200, {
                meetings: db.meetings
            });
        }

        if (p === '/api/admin/meetings' && method === 'POST') {

            const b = await bodyJSON(req);

            const title = clean(b.title, 150);
            const date = clean(b.date, 40);
            const place = clean(b.place, 150);

            if (!title || !date || !place) {

                return send(res, 400, {
                    error: 'Titre, date et lieu requis.'
                });
            }

            const meeting = {
                id: id(),
                title,
                date,
                place,
                agenda: clean(b.agenda, 3000),
                minutes: '',
                published: true,
                createdAt: new Date().toISOString()
            };

            db.meetings.push(meeting);

            writeDB(db);

            return send(res, 201, {
                meeting
            });
        }

        const meetingMatch = p.match(
            /^\/api\/admin\/meetings\/([^/]+)$/
        );

        if (meetingMatch && method === 'PATCH') {

            const meeting = db.meetings.find(
                x => x.id === meetingMatch[1]
            );

            if (!meeting) {

                return send(res, 404, {
                    error: 'Réunion introuvable.'
                });
            }

            const b = await bodyJSON(req);

            for (const key of [
                'title',
                'date',
                'place',
                'agenda',
                'minutes'
            ]) {

                if (b[key] !== undefined) {
                    meeting[key] = clean(b[key], 3000);
                }
            }

            if (b.published !== undefined) {
                meeting.published = !!b.published;
            }

            writeDB(db);

            return send(res, 200, {
                meeting
            });
        }

        // Discussions administrateur

        if (p === '/api/admin/discussions' && method === 'GET') {

            return send(res, 200, {
                discussions: db.discussions
            });
        }

        if (p === '/api/admin/discussions' && method === 'DELETE') {

            const b = await bodyJSON(req);

            db.discussions = db.discussions.filter(
                x => x.id !== b.id
            );

            writeDB(db);

            return send(res, 200, {
                ok: true
            });
        }

        // Présences

        if (p === '/api/admin/attendance' && method === 'GET') {

            const meetingId = url.searchParams.get('meetingId');

            return send(res, 200, {

                attendance: db.attendance.filter(
                    x => !meetingId || x.meetingId === meetingId
                )
            });
        }
    }

    // ======================================
    // ACTIONS RÉSERVÉES AUX MEMBRES
    // ======================================

    const member = memberOK(req);

    // Discussions

    if (p === '/api/member/discussions' && method === 'POST') {

        if (!member) return unauthorized(res);

        const b = await bodyJSON(req);

        const text = clean(b.text, 2000);

        if (text.length < 3) {

            return send(res, 400, {
                error: 'Votre avis est trop court.'
            });
        }

        const db = readDB();

        const discussion = {
            id: id(),
            memberId: member.id,
            memberName: member.name,
            text,
            published: true,
            createdAt: new Date().toISOString()
        };

        db.discussions.push(discussion);

        writeDB(db);

        return send(res, 201, {
            discussion
        });
    }

    // Réactions

    const react = p.match(
        /^\/api\/member\/announcements\/([^/]+)\/react$/
    );

    if (react && method === 'POST') {

        if (!member) return unauthorized(res);

        const db = readDB();
        const aid = react[1];

        if (!db.announcements.some(
            a => a.id === aid && a.published
        )) {

            return send(res, 404, {
                error: 'Publication introuvable.'
            });
        }

        const index = db.reactions.findIndex(
            x =>
                x.announcementId === aid &&
                x.memberId === member.id
        );

        if (index >= 0) {

            db.reactions.splice(index, 1);

        } else {

            db.reactions.push({
                id: id(),
                announcementId: aid,
                memberId: member.id,
                createdAt: new Date().toISOString()
            });
        }

        writeDB(db);

        return send(res, 200, {
            liked: index < 0
        });
    }

    // Commentaires

    const comment = p.match(
        /^\/api\/member\/announcements\/([^/]+)\/comments$/
    );

    if (comment && method === 'POST') {

        if (!member) return unauthorized(res);

        const b = await bodyJSON(req);

        const text = clean(b.text, 1200);

        if (text.length < 2) {

            return send(res, 400, {
                error: 'Commentaire trop court.'
            });
        }

        const db = readDB();

        if (!db.announcements.some(
            a => a.id === comment[1] && a.published
        )) {

            return send(res, 404, {
                error: 'Publication introuvable.'
            });
        }

        const newComment = {
            id: id(),
            announcementId: comment[1],
            memberId: member.id,
            memberName: member.name,
            text,
            createdAt: new Date().toISOString()
        };

        db.comments.push(newComment);

        writeDB(db);

        return send(res, 201, {
            comment: newComment
        });
    }

    // Présence aux réunions

    const attend = p.match(
        /^\/api\/member\/meetings\/([^/]+)\/attendance$/
    );

    if (attend && method === 'POST') {

        if (!member) return unauthorized(res);

        const b = await bodyJSON(req);

        if (!['present', 'absent', 'maybe'].includes(b.status)) {

            return send(res, 400, {
                error: 'Réponse invalide.'
            });
        }

        const db = readDB();

        if (!db.meetings.some(
            m => m.id === attend[1] && m.published
        )) {

            return send(res, 404, {
                error: 'Réunion introuvable.'
            });
        }

        let attendance = db.attendance.find(
            x =>
                x.meetingId === attend[1] &&
                x.memberId === member.id
        );

        if (attendance) {

            attendance.status = b.status;

        } else {

            db.attendance.push({
                id: id(),
                meetingId: attend[1],
                memberId: member.id,
                memberName: member.name,
                status: b.status
            });
        }

        writeDB(db);

        return send(res, 200, {
            ok: true
        });
    }

    return false;
}

// ==========================================
// CONFIGURATION CORS
// ==========================================

function applyCors(req, res) {

    const configuredOrigins = [
        process.env.FRONTEND_URL || '',
        ...(process.env.FRONTEND_URLS || '').split(',')
    ];

    const allowedOrigins = [
        ...configuredOrigins
            .map(value => value.trim())
            .filter(Boolean),

        'http://localhost:3000',
        'http://localhost:5500',
        'http://127.0.0.1:5500'
    ];

    const origin = req.headers.origin;

    if (origin && allowedOrigins.includes(origin)) {

        res.setHeader(
            'Access-Control-Allow-Origin',
            origin
        );

        res.setHeader(
            'Access-Control-Allow-Credentials',
            'true'
        );

        res.setHeader('Vary', 'Origin');
    }

    res.setHeader(
        'Access-Control-Allow-Methods',
        'GET, POST, PATCH, DELETE, OPTIONS'
    );

    res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization'
    );

    if (req.method === 'OPTIONS') {

        res.writeHead(204);
        res.end();

        return true;
    }

    return false;
}

// ==========================================
// FICHIERS STATIQUES
// ==========================================

const MIME = {

    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.ico': 'image/x-icon'
};

// ==========================================
// SERVEUR PRINCIPAL
// ==========================================

const server = http.createServer(async (req, res) => {

    if (applyCors(req, res)) return;

    try {

        const url = new URL(
            req.url,
            `http://${req.headers.host || 'localhost'}`
        );

        // Routes API

        if (url.pathname.startsWith('/api/')) {

            const handled = await api(req, res, url);

            if (handled !== false) return;

            return send(res, 404, {
                error: 'Route API introuvable.'
            });
        }

        // Fichiers publics

        let pathname = decodeURIComponent(url.pathname);

        if (pathname === '/') {
            pathname = '/index.html';
        }

        const target = path.normalize(
            path.join(PUBLIC, pathname)
        );

        const relativeTarget = path.relative(PUBLIC, target);

        if (
            relativeTarget.startsWith('..') ||
            path.isAbsolute(relativeTarget)
        ) {

            return send(
                res,
                403,
                'Forbidden',
                'text/plain'
            );
        }

        fs.readFile(target, (err, data) => {

            if (err) {

                return send(
                    res,
                    404,
                    'Page introuvable',
                    'text/plain; charset=utf-8'
                );
            }

            send(
                res,
                200,
                data,
                MIME[path.extname(target)] ||
                'application/octet-stream'
            );
        });

    } catch (err) {

        console.error('Erreur serveur :', err);

        if (!res.headersSent) {

            send(res, 500, {
                error: 'Erreur interne du serveur.'
            });

        } else {

            res.end();
        }
    }
});

// ==========================================
// DÉMARRAGE
// ==========================================

server.listen(PORT, () => {

    console.log(`DO7U lancé sur le port ${PORT}`);

});
