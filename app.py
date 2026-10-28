import os, sqlite3, csv, io, secrets, functools
from datetime import date, datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, g, render_template, request, redirect, url_for, flash, Response, abort, session

APP_TITLE = 'Gestión de Riesgos de Seguridad de la Información'
DB_PATH = os.environ.get('DB_PATH', '/data/sgsi.db')
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 8

PROBABILITY = {1:'Muy improbable',2:'Improbable',3:'Moderada',4:'Probable',5:'Casi certeza'}
IMPACT = {1:'Insignificante',2:'Menor',3:'Moderado',4:'Mayor',5:'Catastrófico'}
TREATMENTS = ['Reducir','Aceptar','Evitar','Compartir/Transferir']
ASSET_TYPES = ['Software','Hardware','Servicios','Personal','Instalaciones','Información','Proveedor','Proceso']

# Catálogo inicial suministrado por la institución. La fuente se deriva del evento seleccionado.
THREAT_CATALOG = [
('Daño Físico','Incendio','A, D, E'),('Daño Físico','Daños por agua','A, D, E'),('Daño Físico','Contaminación','A, D, E'),('Daño Físico','Accidente grave','A, D, E'),('Daño Físico','Destrucción de equipo o medios','A, D, E'),('Daño Físico','Polvo, corrosión, congelamiento','A, D, E'),
('Eventos Naturales','Fenómeno climático','E'),('Eventos Naturales','Fenómeno sísmico','E'),('Eventos Naturales','Fenómeno volcánico','E'),('Eventos Naturales','Fenómeno meteorológico','E'),('Eventos Naturales','Inundación','E'),
('Pérdida de servicios esenciales','Falla de sistema de aire acondicionado o suministro de agua','A, D'),('Pérdida de servicios esenciales','Pérdida de suministro eléctrico','A, D, E'),('Pérdida de servicios esenciales','Falla de equipo de telecomunicaciones','A, D'),
('Perturbaciones debido a radiación','Radiación electromagnética','A, D, E'),('Perturbaciones debido a radiación','Radiación térmica','A, D, E'),('Perturbaciones debido a radiación','Pulsos electromagnéticos','A, D, E'),
('Compromiso de la información','Interceptación de señales de interferencia comprometedoras','D'),('Compromiso de la información','Espionaje remoto','D'),('Compromiso de la información','Escuchas a escondidas','D'),('Compromiso de la información','Robo de documentos o medios','D'),('Compromiso de la información','Robo de equipo','D'),('Compromiso de la información','Recuperación de medios reciclados o desechados','D'),('Compromiso de la información','Divulgación','A, D'),('Compromiso de la información','Datos de fuentes no confiables','A, D'),('Compromiso de la información','Alteración de hardware','D'),('Compromiso de la información','Alteración de software','A, D'),('Compromiso de la información','Detección de ubicación','D'),
('Fallas técnicas','Falla de equipo','A'),('Fallas técnicas','Mal funcionamiento de equipo','A'),('Fallas técnicas','Saturación del sistema de información','A, D'),('Fallas técnicas','Mal funcionamiento de software','A'),('Fallas técnicas','Violación de mantenibilidad del sistema de información','A, D'),
('Acciones no autorizadas','Uso de equipo no autorizado','D'),('Acciones no autorizadas','Copia fraudulenta de software','D'),('Acciones no autorizadas','Uso de software falsificado o copiado','A, D'),('Acciones no autorizadas','Corrupción de los datos','D'),('Acciones no autorizadas','Procesamiento ilegal de los datos','D'),
('Comprometimiento de funciones','Error de uso','A'),('Comprometimiento de funciones','Abuso de derechos','A, D'),('Comprometimiento de funciones','Falsificación derechos','D'),('Comprometimiento de funciones','Negación de acciones','D'),('Comprometimiento de funciones','Violación de disponibilidad de personal','A, D, E')
]

ANNEX_A_CONTROLS = [
('A.5.1','Políticas de seguridad de la información'),('A.5.2','Roles y responsabilidades de seguridad de la información'),('A.5.3','Segregación de funciones'),('A.5.4','Responsabilidades de la dirección'),('A.5.5','Contacto con autoridades'),('A.5.6','Contacto con grupos de interés especial'),('A.5.7','Inteligencia de amenazas'),('A.5.8','Seguridad de la información en la gestión de proyectos'),('A.5.9','Inventario de información y otros activos asociados'),('A.5.10','Uso aceptable de información y activos asociados'),('A.5.11','Devolución de activos'),('A.5.12','Clasificación de la información'),('A.5.13','Etiquetado de la información'),('A.5.14','Transferencia de información'),('A.5.15','Control de acceso'),('A.5.16','Gestión de identidades'),('A.5.17','Información de autenticación'),('A.5.18','Derechos de acceso'),('A.5.19','Seguridad de la información en relaciones con proveedores'),('A.5.20','Seguridad de la información en acuerdos con proveedores'),('A.5.21','Seguridad de la cadena de suministro TIC'),('A.5.22','Seguimiento, revisión y gestión de cambios de servicios de proveedores'),('A.5.23','Seguridad de la información para servicios en la nube'),('A.5.24','Planificación y preparación para gestión de incidentes'),('A.5.25','Evaluación y decisión sobre eventos de seguridad'),('A.5.26','Respuesta a incidentes de seguridad de la información'),('A.5.27','Aprendizaje a partir de incidentes de seguridad'),('A.5.28','Recopilación de evidencias'),('A.5.29','Seguridad de la información durante interrupciones'),('A.5.30','Preparación de las TIC para la continuidad del negocio'),('A.5.31','Requisitos legales, reglamentarios y contractuales'),('A.5.32','Derechos de propiedad intelectual'),('A.5.33','Protección de registros'),('A.5.34','Privacidad y protección de datos personales'),('A.5.35','Revisión independiente de la seguridad de la información'),('A.5.36','Cumplimiento de políticas, reglas y normas de seguridad'),('A.5.37','Procedimientos operativos documentados'),
('A.6.1','Selección de personal'),('A.6.2','Términos y condiciones de empleo'),('A.6.3','Concienciación, educación y formación en seguridad'),('A.6.4','Proceso disciplinario'),('A.6.5','Responsabilidades tras término o cambio de empleo'),('A.6.6','Acuerdos de confidencialidad o no divulgación'),('A.6.7','Trabajo remoto'),('A.6.8','Notificación de eventos de seguridad de la información'),
('A.7.1','Perímetros de seguridad física'),('A.7.2','Acceso físico'),('A.7.3','Protección de oficinas, salas e instalaciones'),('A.7.4','Monitoreo de seguridad física'),('A.7.5','Protección frente a amenazas físicas y ambientales'),('A.7.6','Trabajo en áreas seguras'),('A.7.7','Escritorio y pantalla limpios'),('A.7.8','Ubicación y protección de equipos'),('A.7.9','Seguridad de activos fuera de las instalaciones'),('A.7.10','Medios de almacenamiento'),('A.7.11','Servicios de soporte'),('A.7.12','Seguridad del cableado'),('A.7.13','Mantenimiento de equipos'),('A.7.14','Eliminación segura o reutilización de equipos'),
('A.8.1','Dispositivos de usuario final'),('A.8.2','Derechos de acceso privilegiado'),('A.8.3','Restricción de acceso a la información'),('A.8.4','Acceso al código fuente'),('A.8.5','Autenticación segura'),('A.8.6','Gestión de capacidad'),('A.8.7','Protección contra malware'),('A.8.8','Gestión de vulnerabilidades técnicas'),('A.8.9','Gestión de configuración'),('A.8.10','Eliminación de información'),('A.8.11','Enmascaramiento de datos'),('A.8.12','Prevención de fuga de datos'),('A.8.13','Copias de seguridad de información'),('A.8.14','Redundancia de instalaciones de procesamiento'),('A.8.15','Registro de eventos'),('A.8.16','Actividades de monitoreo'),('A.8.17','Sincronización de relojes'),('A.8.18','Uso de programas utilitarios privilegiados'),('A.8.19','Instalación de software en sistemas operacionales'),('A.8.20','Seguridad de redes'),('A.8.21','Seguridad de servicios de red'),('A.8.22','Segregación de redes'),('A.8.23','Filtrado web'),('A.8.24','Uso de criptografía'),('A.8.25','Ciclo de vida de desarrollo seguro'),('A.8.26','Requisitos de seguridad de aplicaciones'),('A.8.27','Arquitectura segura y principios de ingeniería'),('A.8.28','Codificación segura'),('A.8.29','Pruebas de seguridad en desarrollo y aceptación'),('A.8.30','Desarrollo externalizado'),('A.8.31','Separación de desarrollo, pruebas y producción'),('A.8.32','Gestión de cambios'),('A.8.33','Información de prueba'),('A.8.34','Protección de sistemas durante pruebas de auditoría')
]

THREAT_CATEGORIES = list(dict.fromkeys(x[0] for x in THREAT_CATALOG))
CONTROL_OPPORTUNITIES = ['Preventivo','Detectivo','Correctivo','Mixto']
CONTROL_PERIODICITIES = ['Continuo/permanente','Diario','Semanal','Mensual','Trimestral','Semestral','Anual','A demanda']
CONTROL_AUTOMATIONS = ['Automático','Semiautomático','Manual']

# Estimación heurística de diseño: oportunidad (máx. 40) + periodicidad (máx. 30) + automatización (máx. 30).
OPPORTUNITY_POINTS = {'Preventivo':40,'Detectivo':30,'Correctivo':20,'Mixto':35}
PERIODICITY_POINTS = {'Continuo/permanente':30,'Diario':28,'Semanal':24,'Mensual':20,'Trimestral':15,'Semestral':12,'Anual':10,'A demanda':5}
AUTOMATION_POINTS = {'Automático':30,'Semiautomático':20,'Manual':10}

def estimate_effectiveness(opportunity, periodicity, automation):
    return OPPORTUNITY_POINTS.get(opportunity, 0) + PERIODICITY_POINTS.get(periodicity, 0) + AUTOMATION_POINTS.get(automation, 0)

def next_risk_code(db):
    import re
    highest = 0
    for row in db.execute('SELECT code FROM risks WHERE code IS NOT NULL'):
        match = re.fullmatch(r'RI-(\d+)', (row['code'] or '').strip(), re.IGNORECASE)
        if match: highest = max(highest, int(match.group(1)))
    return f'RI-{highest + 1:04d}'

# Criterios iniciales configurables. Validar formalmente con la institución antes de usar como metodología oficial.
def risk_level(score):
    if score <= 4: return 'Bajo'
    if score <= 9: return 'Moderado'
    if score <= 16: return 'Alto'
    return 'Crítico'

def get_db():
    if 'db' not in g:
        os.makedirs(os.path.dirname(DB_PATH) or '.', exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    db = g.pop('db', None)
    if db is not None: db.close()

def init_db():
    db = get_db()
    db.executescript('''
    CREATE TABLE IF NOT EXISTS assets (
      id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE, name TEXT NOT NULL,
      asset_type TEXT NOT NULL DEFAULT 'Software', subtype TEXT, description TEXT,
      owner TEXT, confidentiality INTEGER DEFAULT 3, integrity INTEGER DEFAULT 3,
      availability INTEGER DEFAULT 3, criticality INTEGER DEFAULT 3, status TEXT DEFAULT 'Activo',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS risks (
      id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE, asset_id INTEGER,
      name TEXT NOT NULL, description TEXT, url_ip TEXT, threat_category TEXT,
      threat_name TEXT, threat_source TEXT, threat_value INTEGER DEFAULT 3,
      vulnerability TEXT, vulnerability_value INTEGER DEFAULT 3,
      probability INTEGER NOT NULL DEFAULT 3, operational_impact INTEGER DEFAULT 3,
      reputational_impact INTEGER DEFAULT 3, political_impact INTEGER DEFAULT 3,
      regulatory_impact INTEGER DEFAULT 3, impact INTEGER NOT NULL DEFAULT 3,
      inherent_score INTEGER DEFAULT 9, inherent_level TEXT DEFAULT 'Moderado',
      treatment_option TEXT DEFAULT 'Reducir', controls TEXT, control_opportunity TEXT,
      periodicity TEXT, automation TEXT, effectiveness INTEGER DEFAULT 0,
      exposure INTEGER DEFAULT 100, residual_probability INTEGER DEFAULT 3,
      residual_impact INTEGER DEFAULT 3, residual_score INTEGER DEFAULT 9,
      residual_level TEXT DEFAULT 'Moderado', observations TEXT, risk_owner TEXT,
      status TEXT DEFAULT 'Abierto', reviewed_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT, risk_id INTEGER NOT NULL,
      control TEXT, action TEXT NOT NULL, responsible TEXT, start_date TEXT, due_date TEXT,
      product TEXT, evidence TEXT, status TEXT DEFAULT 'Pendiente', progress INTEGER DEFAULT 0,
      observations TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(risk_id) REFERENCES risks(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT, entity TEXT, entity_id INTEGER,
      operation TEXT, detail TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'consulta', active INTEGER NOT NULL DEFAULT 1,
      must_change_password INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS controls (
      id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL,
      category TEXT NOT NULL, title TEXT NOT NULL, applicable INTEGER,
      applicability_justification TEXT DEFAULT '', owner TEXT DEFAULT '',
      implementation_status TEXT NOT NULL DEFAULT 'No iniciado',
      implementation_notes TEXT DEFAULT '', evidence TEXT DEFAULT '',
      reviewed_at TEXT DEFAULT '', source TEXT DEFAULT 'ISO 27001:2022 Anexo A'
    );
    CREATE TABLE IF NOT EXISTS risk_controls (
      risk_id INTEGER NOT NULL, control_id INTEGER NOT NULL,
      PRIMARY KEY(risk_id,control_id), FOREIGN KEY(risk_id) REFERENCES risks(id) ON DELETE CASCADE,
      FOREIGN KEY(control_id) REFERENCES controls(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS action_controls (
      action_id INTEGER NOT NULL, control_id INTEGER NOT NULL,
      PRIMARY KEY(action_id,control_id), FOREIGN KEY(action_id) REFERENCES actions(id) ON DELETE CASCADE,
      FOREIGN KEY(control_id) REFERENCES controls(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS action_observations (
      id INTEGER PRIMARY KEY AUTOINCREMENT, action_id INTEGER NOT NULL,
      user_id INTEGER, observation TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(action_id) REFERENCES actions(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    ''')
    # Migraciones incrementales: conservan los registros existentes.
    def ensure_column(table, column, definition):
        columns = {row['name'] for row in db.execute(f'PRAGMA table_info({table})').fetchall()}
        if column not in columns:
            db.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
    ensure_column('actions', 'closure_status', "TEXT NOT NULL DEFAULT 'No solicitada'")
    ensure_column('actions', 'closure_validated_by', 'INTEGER')
    ensure_column('actions', 'closure_validated_at', 'TEXT')
    ensure_column('audit_log', 'user_id', 'INTEGER')
    db.executescript('''
    CREATE TABLE IF NOT EXISTS action_evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT, action_id INTEGER NOT NULL,
      description TEXT NOT NULL, reference TEXT DEFAULT '', submitted_by INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(action_id) REFERENCES actions(id) ON DELETE CASCADE,
      FOREIGN KEY(submitted_by) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS risk_reevaluations (
      id INTEGER PRIMARY KEY AUTOINCREMENT, risk_id INTEGER NOT NULL,
      previous_probability INTEGER NOT NULL, previous_impact INTEGER NOT NULL,
      previous_score INTEGER NOT NULL, previous_level TEXT NOT NULL,
      new_probability INTEGER NOT NULL, new_impact INTEGER NOT NULL,
      new_score INTEGER NOT NULL, new_level TEXT NOT NULL,
      justification TEXT NOT NULL, responsible_id INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(risk_id) REFERENCES risks(id) ON DELETE CASCADE,
      FOREIGN KEY(responsible_id) REFERENCES users(id) ON DELETE SET NULL
    );
    ''')
    for code, title in ANNEX_A_CONTROLS:
        category = {'A.5':'Organizacionales','A.6':'Personas','A.7':'Físicos','A.8':'Tecnológicos'}[code[:3]]
        db.execute('INSERT OR IGNORE INTO controls(code,category,title) VALUES(?,?,?)',(code,category,title))
    db.commit()

def current_user():
    uid = session.get('user_id')
    return get_db().execute('SELECT * FROM users WHERE id=? AND active=1',(uid,)).fetchone() if uid else None

def role_required(*roles):
    def decorate(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            user=current_user()
            if not user:
                return redirect(url_for('login', next=request.path))
            if user['role'] not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorate

@app.before_request
def enforce_login():
    if request.endpoint in ('login','setup','static','health') or request.endpoint is None:
        return
    db=get_db()
    if db.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
        return redirect(url_for('setup'))
    if not current_user():
        return redirect(url_for('login', next=request.path))

@app.context_processor
def inject_user():
    return {'current_user': current_user()}

@app.route('/setup', methods=['GET','POST'])
def setup():
    db=get_db()
    if db.execute('SELECT COUNT(*) FROM users').fetchone()[0] > 0:
        return redirect(url_for('login'))
    if request.method == 'POST':
        username=request.form.get('username','').strip().lower()
        display=request.form.get('display_name','').strip()
        password=request.form.get('password','')
        confirm=request.form.get('confirm','')
        if not username or not display or len(password)<12:
            flash('Completa los campos. La contraseña debe tener al menos 12 caracteres.','error')
        elif password != confirm:
            flash('Las contraseñas no coinciden.','error')
        else:
            db.execute('INSERT INTO users(username,display_name,password_hash,role,active,must_change_password) VALUES(?,?,?,?,1,0)',(username,display,generate_password_hash(password),'admin'))
            db.commit(); session.clear(); session['user_id']=db.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()['id']; session.permanent=True
            flash('Administrador inicial creado.','success'); return redirect(url_for('dashboard'))
    return render_template('setup.html',title='Configuración inicial')

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user(): return redirect(url_for('dashboard'))
    if request.method=='POST':
        username=request.form.get('username','').strip().lower(); password=request.form.get('password','')
        user=get_db().execute('SELECT * FROM users WHERE username=? AND active=1',(username,)).fetchone()
        if user and check_password_hash(user['password_hash'],password):
            session.clear(); session['user_id']=user['id']; session.permanent=True
            if user['must_change_password']: return redirect(url_for('change_password'))
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash('Usuario o contraseña incorrectos.','error')
    return render_template('login.html',title='Iniciar sesión')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear(); return redirect(url_for('login'))

@app.route('/password', methods=['GET','POST'])
@role_required('admin','gestor','consulta')
def change_password():
    user=current_user()
    if request.method=='POST':
        old=request.form.get('old_password',''); new=request.form.get('password',''); confirm=request.form.get('confirm','')
        if not check_password_hash(user['password_hash'],old): flash('La contraseña actual no es correcta.','error')
        elif len(new)<12: flash('La nueva contraseña debe tener al menos 12 caracteres.','error')
        elif new!=confirm: flash('Las contraseñas nuevas no coinciden.','error')
        else:
            get_db().execute('UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?',(generate_password_hash(new),user['id'])); get_db().commit()
            flash('Contraseña actualizada.','success'); return redirect(url_for('dashboard'))
    return render_template('change_password.html',title='Cambiar contraseña')

@app.route('/users', methods=['GET','POST'])
@role_required('admin')
def users():
    db=get_db()
    if request.method=='POST':
        username=request.form.get('username','').strip().lower(); display=request.form.get('display_name','').strip(); password=request.form.get('password',''); role=request.form.get('role','gestor')
        if not username or not display or len(password)<12 or role not in ('admin','gestor','consulta'):
            flash('Revisa los campos. La contraseña debe tener al menos 12 caracteres.','error')
        else:
            try:
                db.execute('INSERT INTO users(username,display_name,password_hash,role,active,must_change_password) VALUES(?,?,?,?,1,1)',(username,display,generate_password_hash(password),role)); db.commit()
                flash('Usuario creado; deberá cambiar la contraseña al ingresar.','success')
            except sqlite3.IntegrityError: flash('Ese nombre de usuario ya existe.','error')
        return redirect(url_for('users'))
    rows=db.execute('SELECT id,username,display_name,role,active,created_at FROM users ORDER BY display_name').fetchall()
    return render_template('users.html',title='Administración de usuarios',users=rows)

@app.route('/users/<int:user_id>/toggle', methods=['POST'])
@role_required('admin')
def user_toggle(user_id):
    if current_user()['id']==user_id: flash('No puedes desactivar tu propia cuenta.','error')
    else:
        db=get_db(); db.execute('UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?',(user_id,)); db.commit(); flash('Estado de usuario actualizado.','success')
    return redirect(url_for('users'))

def audit(entity, entity_id, operation, detail=''):
    user = current_user()
    get_db().execute('INSERT INTO audit_log(entity,entity_id,operation,detail,user_id) VALUES(?,?,?,?,?)',
                     (entity, entity_id, operation, detail, user['id'] if user else None))
    get_db().commit()

def calculate_risk(probability, impact):
    score = int(probability) * int(impact)
    return score, risk_level(score)

def form_int(name, default=3, minv=1, maxv=5):
    try: return max(minv, min(maxv, int(request.form.get(name, default))))
    except (TypeError, ValueError): return default

def refresh_risk(risk_id):
    db = get_db(); r = db.execute('SELECT * FROM risks WHERE id=?', (risk_id,)).fetchone()
    if not r: return
    score, level = calculate_risk(r['probability'], r['impact'])
    rs, rl = calculate_risk(r['residual_probability'], r['residual_impact'])
    db.execute('UPDATE risks SET inherent_score=?, inherent_level=?, residual_score=?, residual_level=?, exposure=? WHERE id=?',
               (score, level, rs, rl, 100-int(r['effectiveness'] or 0), risk_id))
    db.commit()

@app.route('/')
@role_required('admin','gestor','consulta')
def dashboard():
    db=get_db()
    total=db.execute('SELECT COUNT(*) n FROM risks').fetchone()['n']
    by_level={x:db.execute('SELECT COUNT(*) n FROM risks WHERE inherent_level=?',(x,)).fetchone()['n'] for x in ['Crítico','Alto','Moderado','Bajo']}
    above=db.execute("SELECT COUNT(*) n FROM risks WHERE inherent_level IN ('Crítico','Alto')").fetchone()['n']
    open_actions=db.execute("SELECT COUNT(*) n FROM actions WHERE status NOT IN ('Completada','Cancelada')").fetchone()['n']
    overdue=db.execute("SELECT COUNT(*) n FROM actions WHERE due_date IS NOT NULL AND due_date<>'' AND due_date < ? AND status NOT IN ('Completada','Cancelada')",(date.today().isoformat(),)).fetchone()['n']
    soa_total=db.execute('SELECT COUNT(*) FROM controls').fetchone()[0]
    soa_applicable=db.execute('SELECT COUNT(*) FROM controls WHERE applicable=1').fetchone()[0]
    soa_implemented=db.execute("SELECT COUNT(*) FROM controls WHERE applicable=1 AND implementation_status='Implementado'").fetchone()[0]
    soa_pending=db.execute('SELECT COUNT(*) FROM controls WHERE applicable IS NULL').fetchone()[0]
    risks=db.execute('''SELECT r.*, a.name asset_name FROM risks r LEFT JOIN assets a ON a.id=r.asset_id ORDER BY CASE r.inherent_level WHEN 'Crítico' THEN 1 WHEN 'Alto' THEN 2 WHEN 'Moderado' THEN 3 ELSE 4 END, r.inherent_score DESC LIMIT 8''').fetchall()
    return render_template('dashboard.html', title=APP_TITLE, total=total, by_level=by_level, above=above, open_actions=open_actions, overdue=overdue, risks=risks, soa_total=soa_total, soa_applicable=soa_applicable, soa_implemented=soa_implemented, soa_pending=soa_pending)

@app.route('/assets')
@role_required('admin','gestor','consulta')
def assets():
    rows=get_db().execute('SELECT * FROM assets ORDER BY name').fetchall()
    return render_template('assets.html', title='Inventario de activos', assets=rows)

@app.route('/assets/new', methods=['GET','POST'])
@role_required('admin')
def asset_new():
    if request.method=='POST':
        db=get_db(); code=request.form.get('code','').strip() or None; name=request.form.get('name','').strip()
        if not name: flash('El nombre del activo es obligatorio.','error'); return redirect(url_for('asset_new'))
        try:
            cur=db.execute('''INSERT INTO assets(code,name,asset_type,subtype,description,owner,confidentiality,integrity,availability,criticality,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                (code,name,request.form.get('asset_type','Software'),request.form.get('subtype',''),request.form.get('description',''),request.form.get('owner',''),form_int('confidentiality'),form_int('integrity'),form_int('availability'),form_int('criticality'),request.form.get('status','Activo')))
            audit('asset',cur.lastrowid,'create',name); db.commit(); flash('Activo creado.','success'); return redirect(url_for('assets'))
        except sqlite3.IntegrityError: flash('Ese código de activo ya existe.','error')
    return render_template('asset_form.html', title='Nuevo activo', asset=None, asset_types=ASSET_TYPES)

@app.route('/assets/<int:asset_id>/edit', methods=['GET','POST'])
@role_required('admin')
def asset_edit(asset_id):
    db=get_db(); a=db.execute('SELECT * FROM assets WHERE id=?',(asset_id,)).fetchone()
    if not a: abort(404)
    if request.method=='POST':
        db.execute('''UPDATE assets SET code=?,name=?,asset_type=?,subtype=?,description=?,owner=?,confidentiality=?,integrity=?,availability=?,criticality=?,status=? WHERE id=?''',
            (request.form.get('code','').strip() or None,request.form.get('name','').strip(),request.form.get('asset_type','Software'),request.form.get('subtype',''),request.form.get('description',''),request.form.get('owner',''),form_int('confidentiality'),form_int('integrity'),form_int('availability'),form_int('criticality'),request.form.get('status','Activo'),asset_id))
        audit('asset',asset_id,'update',request.form.get('name','')); db.commit(); flash('Activo actualizado.','success'); return redirect(url_for('assets'))
    return render_template('asset_form.html', title='Editar activo', asset=a, asset_types=ASSET_TYPES)

@app.route('/risks')
@role_required('admin','gestor','consulta')
def risks():
    db=get_db(); search=request.args.get('q','').strip(); level=request.args.get('level','')
    sql='SELECT r.*,a.name asset_name FROM risks r LEFT JOIN assets a ON a.id=r.asset_id WHERE 1=1'; args=[]
    if search: sql+=' AND (r.code LIKE ? OR r.name LIKE ? OR a.name LIKE ?)'; args += [f'%{search}%']*3
    if level: sql+=' AND r.inherent_level=?'; args.append(level)
    sql+=" ORDER BY CASE r.inherent_level WHEN 'Crítico' THEN 1 WHEN 'Alto' THEN 2 WHEN 'Moderado' THEN 3 ELSE 4 END, r.code"
    rows=db.execute(sql,args).fetchall()
    return render_template('risks.html', title='Registro de riesgos', risks=rows, q=search, level=level)

@app.route('/risks/new', methods=['GET','POST'])
@role_required('admin')
def risk_new():
    db=get_db(); asset_rows=db.execute("SELECT id,name,code FROM assets WHERE status='Activo' ORDER BY name").fetchall()
    if request.method=='POST':
        name=request.form.get('name','').strip()
        if not name: flash('El nombre del riesgo es obligatorio.','error'); return redirect(url_for('risk_new'))
        prob=form_int('probability'); impact=form_int('impact'); rp=form_int('residual_probability'); ri=form_int('residual_impact')
        opportunity=request.form.get('control_opportunity',''); periodicity=request.form.get('periodicity',''); automation=request.form.get('automation','')
        eff=estimate_effectiveness(opportunity,periodicity,automation)
        threat_name=request.form.get('threat_name',''); threat_category=request.form.get('threat_category',''); threat_source=request.form.get('threat_source','')
        catalog_match=next((x for x in THREAT_CATALOG if x[0]==threat_category and x[1]==threat_name),None)
        if catalog_match: threat_source=catalog_match[2]
        score,level=calculate_risk(prob,impact); rs,rl=calculate_risk(rp,ri)
        db.execute('BEGIN IMMEDIATE')
        code=next_risk_code(db)
        cur=db.execute('''INSERT INTO risks(code,asset_id,name,description,url_ip,threat_category,threat_name,threat_source,threat_value,vulnerability,vulnerability_value,probability,operational_impact,reputational_impact,political_impact,regulatory_impact,impact,inherent_score,inherent_level,treatment_option,controls,control_opportunity,periodicity,automation,effectiveness,exposure,residual_probability,residual_impact,residual_score,residual_level,observations,risk_owner,status,reviewed_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (code,request.form.get('asset_id') or None,name,request.form.get('description',''),request.form.get('url_ip',''),threat_category,threat_name,threat_source,form_int('threat_value'),request.form.get('vulnerability',''),form_int('vulnerability_value'),prob,form_int('operational_impact'),form_int('reputational_impact'),form_int('political_impact'),form_int('regulatory_impact'),impact,score,level,request.form.get('treatment_option','Reducir'),request.form.get('controls',''),opportunity,periodicity,automation,eff,100-eff,rp,ri,rs,rl,request.form.get('observations',''),request.form.get('risk_owner',''),request.form.get('status','Abierto'),date.today().isoformat()))
        audit('risk',cur.lastrowid,'create',f'{code} - {name}')
        for cid in request.form.getlist('control_ids'):
            if db.execute('SELECT 1 FROM controls WHERE id=? AND applicable=1',(cid,)).fetchone(): db.execute('INSERT OR IGNORE INTO risk_controls(risk_id,control_id) VALUES(?,?)',(cur.lastrowid,cid))
        db.commit(); flash(f'Riesgo {code} registrado.','success'); return redirect(url_for('risk_detail',risk_id=cur.lastrowid))
    control_rows=db.execute('SELECT * FROM controls WHERE applicable=1 ORDER BY code').fetchall()
    return render_template('risk_form.html', title='Nuevo riesgo', risk=None, selected_control_ids=[], controls=control_rows, next_code=next_risk_code(db), assets=asset_rows, probability=PROBABILITY, impact_labels=IMPACT, treatments=TREATMENTS, threat_catalog=THREAT_CATALOG, threat_categories=THREAT_CATEGORIES, opportunities=CONTROL_OPPORTUNITIES, periodicities=CONTROL_PERIODICITIES, automations=CONTROL_AUTOMATIONS)

@app.route('/risks/<int:risk_id>')
@role_required('admin','gestor','consulta')
def risk_detail(risk_id):
    db=get_db(); r=db.execute('SELECT r.*,a.name asset_name FROM risks r LEFT JOIN assets a ON a.id=r.asset_id WHERE r.id=?',(risk_id,)).fetchone()
    if not r: abort(404)
    actions=[dict(x) for x in db.execute('SELECT * FROM actions WHERE risk_id=? ORDER BY due_date,id',(risk_id,)).fetchall()]
    for a in actions:
        a['history']=db.execute('SELECT ao.*,u.display_name FROM action_observations ao LEFT JOIN users u ON u.id=ao.user_id WHERE ao.action_id=? ORDER BY ao.created_at,ao.id',(a['id'],)).fetchall()
        a['controls_list']=db.execute('SELECT c.code,c.title FROM action_controls ac JOIN controls c ON c.id=ac.control_id WHERE ac.action_id=? ORDER BY c.code',(a['id'],)).fetchall()
    risk_controls=db.execute('SELECT c.code,c.title FROM risk_controls rc JOIN controls c ON c.id=rc.control_id WHERE rc.risk_id=? ORDER BY c.code',(risk_id,)).fetchall()
    progress_row = db.execute("SELECT COUNT(*) total, COALESCE(AVG(progress),0) avg_progress, SUM(CASE WHEN status='Completada' THEN 1 ELSE 0 END) completed FROM actions WHERE risk_id=? AND status<>'Cancelada'",(risk_id,)).fetchone()
    reevaluations = db.execute('SELECT rr.*,u.display_name FROM risk_reevaluations rr LEFT JOIN users u ON u.id=rr.responsible_id WHERE rr.risk_id=? ORDER BY rr.created_at DESC,rr.id DESC',(risk_id,)).fetchall()
    evidence_by_action = {}
    for action_row in actions:
        evidence_by_action[action_row['id']] = db.execute('SELECT ae.*,u.display_name FROM action_evidence ae LEFT JOIN users u ON u.id=ae.submitted_by WHERE ae.action_id=? ORDER BY ae.created_at DESC,ae.id DESC',(action_row['id'],)).fetchall()
    return render_template('risk_detail.html', title=r['code'] or r['name'], risk=r, actions=actions, risk_controls=risk_controls, today=date.today().isoformat(), treatment_progress=round(progress_row['avg_progress'] or 0), treatment_total=progress_row['total'] or 0, treatment_completed=progress_row['completed'] or 0, reevaluations=reevaluations, evidence_by_action=evidence_by_action)

@app.route('/risks/<int:risk_id>/edit', methods=['GET','POST'])
@role_required('admin')
def risk_edit(risk_id):
    db=get_db(); r=db.execute('SELECT * FROM risks WHERE id=?',(risk_id,)).fetchone()
    if not r: abort(404)
    assets_rows=db.execute("SELECT id,name,code FROM assets WHERE status='Activo' ORDER BY name").fetchall()
    if request.method=='POST':
        prob=form_int('probability'); impact=form_int('impact'); rp=form_int('residual_probability'); ri=form_int('residual_impact'); opportunity=request.form.get('control_opportunity',''); periodicity=request.form.get('periodicity',''); automation=request.form.get('automation',''); eff=estimate_effectiveness(opportunity,periodicity,automation); score,level=calculate_risk(prob,impact); rs,rl=calculate_risk(rp,ri)
        threat_name=request.form.get('threat_name',''); threat_category=request.form.get('threat_category',''); threat_source=request.form.get('threat_source',''); catalog_match=next((x for x in THREAT_CATALOG if x[0]==threat_category and x[1]==threat_name),None)
        if catalog_match: threat_source=catalog_match[2]
        db.execute('''UPDATE risks SET code=?,asset_id=?,name=?,description=?,url_ip=?,threat_category=?,threat_name=?,threat_source=?,threat_value=?,vulnerability=?,vulnerability_value=?,probability=?,operational_impact=?,reputational_impact=?,political_impact=?,regulatory_impact=?,impact=?,inherent_score=?,inherent_level=?,treatment_option=?,controls=?,control_opportunity=?,periodicity=?,automation=?,effectiveness=?,exposure=?,residual_probability=?,residual_impact=?,residual_score=?,residual_level=?,observations=?,risk_owner=?,status=?,reviewed_at=? WHERE id=?''',
        (r['code'],request.form.get('asset_id') or None,request.form.get('name','').strip(),request.form.get('description',''),request.form.get('url_ip',''),threat_category,threat_name,threat_source,form_int('threat_value'),request.form.get('vulnerability',''),form_int('vulnerability_value'),prob,form_int('operational_impact'),form_int('reputational_impact'),form_int('political_impact'),form_int('regulatory_impact'),impact,score,level,request.form.get('treatment_option','Reducir'),request.form.get('controls',''),opportunity,periodicity,automation,eff,100-eff,rp,ri,rs,rl,request.form.get('observations',''),request.form.get('risk_owner',''),request.form.get('status','Abierto'),date.today().isoformat(),risk_id))
        audit('risk',risk_id,'update',request.form.get('name',''))
        db.execute('DELETE FROM risk_controls WHERE risk_id=?',(risk_id,))
        for cid in request.form.getlist('control_ids'):
            if db.execute('SELECT 1 FROM controls WHERE id=? AND applicable=1',(cid,)).fetchone(): db.execute('INSERT OR IGNORE INTO risk_controls(risk_id,control_id) VALUES(?,?)',(risk_id,cid))
        db.commit(); flash('Riesgo actualizado.','success'); return redirect(url_for('risk_detail',risk_id=risk_id))
    control_rows=db.execute('SELECT * FROM controls WHERE applicable=1 OR id IN (SELECT control_id FROM risk_controls WHERE risk_id=?) ORDER BY code',(risk_id,)).fetchall()
    selected_control_ids=[str(x['control_id']) for x in db.execute('SELECT control_id FROM risk_controls WHERE risk_id=?',(risk_id,)).fetchall()]
    return render_template('risk_form.html', title='Editar riesgo', risk=r, selected_control_ids=selected_control_ids, controls=control_rows, next_code=r['code'], assets=assets_rows, probability=PROBABILITY, impact_labels=IMPACT, treatments=TREATMENTS, threat_catalog=THREAT_CATALOG, threat_categories=THREAT_CATEGORIES, opportunities=CONTROL_OPPORTUNITIES, periodicities=CONTROL_PERIODICITIES, automations=CONTROL_AUTOMATIONS)

@app.route('/risks/<int:risk_id>/actions/new', methods=['GET','POST'])
@role_required('admin')
def action_new(risk_id):
    db=get_db(); r=db.execute('SELECT * FROM risks WHERE id=?',(risk_id,)).fetchone()
    if not r: abort(404)
    if request.method=='POST':
        action=request.form.get('action','').strip()
        if not action: flash('La acción es obligatoria.','error'); return redirect(url_for('action_new',risk_id=risk_id))
        cur=db.execute('INSERT INTO actions(risk_id,control,action,responsible,start_date,due_date,product,evidence,status,progress,observations) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
        (risk_id,request.form.get('control',''),action,request.form.get('responsible',''),request.form.get('start_date',''),request.form.get('due_date',''),request.form.get('product',''),request.form.get('evidence',''),request.form.get('status','Pendiente'),form_int('progress',0,0,100),request.form.get('observations','')))
        audit('action',cur.lastrowid,'create',action)
        for cid in request.form.getlist('control_ids'):
            if db.execute('SELECT 1 FROM controls WHERE id=? AND applicable=1',(cid,)).fetchone(): db.execute('INSERT OR IGNORE INTO action_controls(action_id,control_id) VALUES(?,?)',(cur.lastrowid,cid))
        db.commit(); flash('Acción incorporada al plan.','success'); return redirect(url_for('risk_detail',risk_id=risk_id))
    control_rows=db.execute('SELECT * FROM controls WHERE applicable=1 ORDER BY code').fetchall()
    return render_template('action_form.html', title='Nueva acción de tratamiento', risk=r, action=None, controls=control_rows, selected_control_ids=[])

@app.route('/actions/<int:action_id>/edit', methods=['GET','POST'])
@role_required('admin','gestor','consulta')
def action_edit(action_id):
    db=get_db(); a=db.execute('SELECT * FROM actions WHERE id=?',(action_id,)).fetchone()
    if not a: abort(404)
    r=db.execute('SELECT * FROM risks WHERE id=?',(a['risk_id'],)).fetchone()
    user=current_user(); is_admin=user['role']=='admin'; is_manager=user['role']=='gestor'
    if request.method=='POST':
        if is_admin:
            action=request.form.get('action','').strip()
            if not action: flash('La acción es obligatoria.','error'); return redirect(url_for('action_edit',action_id=action_id))
            db.execute('UPDATE actions SET control=?,action=?,responsible=?,start_date=?,due_date=?,product=?,evidence=?,status=?,progress=? WHERE id=?',
              (request.form.get('control',''),action,request.form.get('responsible',''),request.form.get('start_date',''),request.form.get('due_date',''),request.form.get('product',''),request.form.get('evidence',''),request.form.get('status','Pendiente'),form_int('progress',0,0,100),action_id))
            db.execute('DELETE FROM action_controls WHERE action_id=?',(action_id,))
            for cid in request.form.getlist('control_ids'):
                if db.execute('SELECT 1 FROM controls WHERE id=? AND applicable=1',(cid,)).fetchone(): db.execute('INSERT OR IGNORE INTO action_controls(action_id,control_id) VALUES(?,?)',(action_id,cid))
            audit('action',action_id,'update',action)
        elif is_manager:
            progress=form_int('progress',0,0,100)
            db.execute("UPDATE actions SET progress=?, status=CASE WHEN ?>0 THEN 'En curso' WHEN status IN ('Completada','Pendiente validación') THEN 'En curso' ELSE status END, closure_status=CASE WHEN ?>=100 THEN 'Pendiente de validación' ELSE 'No solicitada' END, closure_validated_by=NULL, closure_validated_at=NULL WHERE id=?",(progress,progress,progress,action_id))
            observation=request.form.get('new_observation','').strip()
            if observation: db.execute('INSERT INTO action_observations(action_id,user_id,observation) VALUES(?,?,?)',(action_id,user['id'],observation))
            audit('action',action_id,'progress_update',f'avance={progress}; observación agregada={bool(observation)}')
        else: abort(403)
        db.commit(); flash('Seguimiento actualizado.','success'); return redirect(url_for('risk_detail',risk_id=a['risk_id']))
    control_rows=db.execute('SELECT * FROM controls WHERE applicable=1 OR id IN (SELECT control_id FROM action_controls WHERE action_id=?) ORDER BY code',(action_id,)).fetchall()
    selected_control_ids=[str(x['control_id']) for x in db.execute('SELECT control_id FROM action_controls WHERE action_id=?',(action_id,)).fetchall()]
    history=db.execute('SELECT ao.*,u.display_name FROM action_observations ao LEFT JOIN users u ON u.id=ao.user_id WHERE ao.action_id=? ORDER BY ao.created_at,ao.id',(action_id,)).fetchall()
    return render_template('action_form.html', title='Editar acción de tratamiento', risk=r, action=a, controls=control_rows, selected_control_ids=selected_control_ids, is_admin=is_admin, is_manager=is_manager, history=history)

@app.route('/treatment')
@role_required('admin','gestor','consulta')
def treatment():
    rows=[dict(x) for x in get_db().execute('''SELECT a.*,r.code risk_code,r.name risk_name,r.inherent_level,r.residual_level,asst.name asset_name FROM actions a JOIN risks r ON r.id=a.risk_id LEFT JOIN assets asst ON asst.id=r.asset_id ORDER BY CASE a.status WHEN 'Atrasada' THEN 1 WHEN 'En curso' THEN 2 WHEN 'Pendiente' THEN 3 ELSE 4 END,a.due_date''').fetchall()]
    for a in rows: a['controls_list']=get_db().execute('SELECT c.code FROM action_controls ac JOIN controls c ON c.id=ac.control_id WHERE ac.action_id=? ORDER BY c.code',(a['id'],)).fetchall()
    status_filter=request.args.get('status','').strip()
    overdue_filter=request.args.get('overdue','') == '1'
    if status_filter:
        rows=[a for a in rows if a['status']==status_filter]
    if overdue_filter:
        rows=[a for a in rows if a['due_date'] and a['due_date'] < date.today().isoformat() and a['status'] not in ('Completada','Cancelada')]
    return render_template('treatment.html', title='Plan de tratamiento', actions=rows, today=date.today().isoformat(), status_filter=status_filter, overdue_filter=overdue_filter)


@app.route('/actions/<int:action_id>/evidence', methods=['POST'])
@role_required('admin','gestor')
def action_add_evidence(action_id):
    db=get_db(); action=db.execute('SELECT * FROM actions WHERE id=?',(action_id,)).fetchone()
    if not action: abort(404)
    description=request.form.get('description','').strip(); reference=request.form.get('reference','').strip()
    if not description:
        flash('Describe la evidencia antes de guardarla.','error')
        return redirect(url_for('action_edit',action_id=action_id))
    user=current_user()
    db.execute('INSERT INTO action_evidence(action_id,description,reference,submitted_by) VALUES(?,?,?,?)',(action_id,description,reference,user['id']))
    audit('action',action_id,'evidence_added',description[:240]); db.commit()
    flash('Evidencia registrada con responsable y fecha.','success')
    return redirect(url_for('risk_detail',risk_id=action['risk_id']))

@app.route('/actions/<int:action_id>/validate-closure', methods=['POST'])
@role_required('admin')
def action_validate_closure(action_id):
    db=get_db(); action=db.execute('SELECT * FROM actions WHERE id=?',(action_id,)).fetchone()
    if not action: abort(404)
    decision=request.form.get('decision','').strip()
    if decision not in ('approve','reject'): abort(400)
    if decision=='approve' and int(action['progress'] or 0)<100:
        flash('No se puede aprobar el cierre: el avance debe ser 100 %.','error')
        return redirect(url_for('risk_detail',risk_id=action['risk_id']))
    user=current_user()
    if decision=='approve':
        db.execute("UPDATE actions SET status='Completada',closure_status='Validada',closure_validated_by=?,closure_validated_at=CURRENT_TIMESTAMP WHERE id=?",(user['id'],action_id))
        detail='Cierre de acción validado por administrador'
    else:
        db.execute("UPDATE actions SET status='En curso',closure_status='Rechazada',closure_validated_by=?,closure_validated_at=CURRENT_TIMESTAMP WHERE id=?",(user['id'],action_id))
        detail='Cierre rechazado; requiere seguimiento'
    audit('action',action_id,'closure_'+decision,detail); db.commit()
    flash('Cierre validado.' if decision=='approve' else 'Cierre rechazado; la acción vuelve a seguimiento.','success')
    return redirect(url_for('risk_detail',risk_id=action['risk_id']))

@app.route('/risks/<int:risk_id>/reevaluate', methods=['GET','POST'])
@role_required('admin')
def risk_reevaluate(risk_id):
    db=get_db(); risk=db.execute('SELECT * FROM risks WHERE id=?',(risk_id,)).fetchone()
    if not risk: abort(404)
    if request.method=='POST':
        justification=request.form.get('justification','').strip()
        if not justification:
            flash('La justificación de la reevaluación es obligatoria.','error')
            return redirect(url_for('risk_reevaluate',risk_id=risk_id))
        np=form_int('residual_probability'); ni=form_int('residual_impact'); score,level=calculate_risk(np,ni); user=current_user()
        db.execute('''INSERT INTO risk_reevaluations(risk_id,previous_probability,previous_impact,previous_score,previous_level,new_probability,new_impact,new_score,new_level,justification,responsible_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
          (risk_id,risk['residual_probability'],risk['residual_impact'],risk['residual_score'],risk['residual_level'],np,ni,score,level,justification,user['id']))
        db.execute('UPDATE risks SET residual_probability=?,residual_impact=?,residual_score=?,residual_level=?,reviewed_at=? WHERE id=?',(np,ni,score,level,date.today().isoformat(),risk_id))
        audit('risk',risk_id,'residual_reevaluation',f"{risk['residual_score']} {risk['residual_level']} -> {score} {level}; {justification[:180]}")
        db.commit(); flash('Reevaluación residual registrada con trazabilidad.','success')
        return redirect(url_for('risk_detail',risk_id=risk_id))
    return render_template('risk_reevaluate.html',title='Reevaluar riesgo residual',risk=risk,probability=PROBABILITY,impact_labels=IMPACT)

@app.route('/reports/risks.csv')
@role_required('admin','gestor','consulta')
def export_risks():
    db=get_db(); rows=db.execute("SELECT r.*,a.name asset_name,COALESCE((SELECT GROUP_CONCAT(c.code, ', ') FROM risk_controls rc JOIN controls c ON c.id=rc.control_id WHERE rc.risk_id=r.id),'') linked_controls FROM risks r LEFT JOIN assets a ON a.id=r.asset_id ORDER BY r.code").fetchall()
    output=io.StringIO(); output.write('\ufeff'); writer=csv.writer(output,delimiter=';')
    writer.writerow(['ID','Nombre del activo','Tipo de activo','Nombre del riesgo','Descripción','URL/IP','Tipo amenaza','Amenaza','Fuente amenaza','Valor amenaza','Vulnerabilidad','Valor vulnerabilidad','Probabilidad inherente','Impacto','Riesgo inherente','Nivel severidad','Opción tratamiento','Controles aplicados','Controles Anexo A vinculados','Efectividad (%)','Exposición (%)','Probabilidad residual','Impacto residual','Valor riesgo residual','Riesgo residual','Responsable del riesgo','Estado','Observaciones'])
    for r in rows: writer.writerow([r['code'],r['asset_name'], '',r['name'],r['description'],r['url_ip'],r['threat_category'],r['threat_name'],r['threat_source'],r['threat_value'],r['vulnerability'],r['vulnerability_value'],r['probability'],r['impact'],r['inherent_score'],r['inherent_level'],r['treatment_option'],r['controls'],r['linked_controls'],r['effectiveness'],r['exposure'],r['residual_probability'],r['residual_impact'],r['residual_score'],r['residual_level'],r['risk_owner'],r['status'],r['observations']])
    return Response(output.getvalue(),mimetype='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename=registro_riesgos.csv'})

@app.route('/reports/treatment.csv')
@role_required('admin','gestor','consulta')
def export_treatment():
    rows=get_db().execute("SELECT a.*,r.code risk_code,r.name risk_name,r.inherent_level,r.residual_level,COALESCE((SELECT GROUP_CONCAT(c.code, ', ') FROM action_controls ac JOIN controls c ON c.id=ac.control_id WHERE ac.action_id=a.id),'') linked_controls FROM actions a JOIN risks r ON r.id=a.risk_id ORDER BY r.code,a.due_date").fetchall()
    output=io.StringIO(); output.write('\ufeff'); w=csv.writer(output,delimiter=';'); w.writerow(['ID riesgo','Riesgo','Nivel inherente','Nivel residual','Control que aborda','Controles Anexo A vinculados','Acción','Responsable(s)','Fecha inicio','Fecha compromiso','Producto entregado','Registro/evidencia','Estado actividad','Avance (%)','Observaciones'])
    for a in rows: w.writerow([a['risk_code'],a['risk_name'],a['inherent_level'],a['residual_level'],a['control'],a['linked_controls'],a['action'],a['responsible'],a['start_date'],a['due_date'],a['product'],a['evidence'],a['status'],a['progress'],a['observations']])
    return Response(output.getvalue(),mimetype='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename=plan_tratamiento.csv'})

@app.route('/soa')
@role_required('admin','gestor','consulta')
def soa():
    db=get_db(); rows=db.execute("""SELECT c.*,
      (SELECT COUNT(*) FROM risk_controls rc WHERE rc.control_id=c.id) risk_count,
      (SELECT COUNT(*) FROM action_controls ac JOIN actions a ON a.id=ac.action_id WHERE ac.control_id=c.id AND a.status NOT IN ('Completada','Cancelada')) open_actions,
      (SELECT COUNT(*) FROM action_controls ac JOIN actions a ON a.id=ac.action_id WHERE ac.control_id=c.id AND a.status='Completada') done_actions
      FROM controls c ORDER BY c.code""").fetchall()
    total=len(rows); applicable=sum(1 for x in rows if x['applicable']==1); excluded=sum(1 for x in rows if x['applicable']==0); pending=total-applicable-excluded
    implemented=sum(1 for x in rows if x['applicable']==1 and x['implementation_status']=='Implementado')
    partial=sum(1 for x in rows if x['applicable']==1 and x['implementation_status']=='Parcialmente implementado')
    in_progress=sum(1 for x in rows if x['applicable']==1 and x['implementation_status']=='En curso')
    return render_template('soa.html',title='Declaración de Aplicabilidad',controls=rows,total=total,applicable=applicable,excluded=excluded,pending=pending,implemented=implemented,partial=partial,in_progress=in_progress,implementation_pct=round(implemented/applicable*100,1) if applicable else None)

@app.route('/soa/controls/<int:control_id>', methods=['GET','POST'])
@role_required('admin')
def soa_control_edit(control_id):
    db=get_db(); c=db.execute('SELECT * FROM controls WHERE id=?',(control_id,)).fetchone()
    if not c: abort(404)
    if request.method=='POST':
        applicable=request.form.get('applicable','')
        applicable_value=None if applicable=='' else (1 if applicable=='1' else 0)
        justification=request.form.get('applicability_justification','').strip()
        if applicable_value==0 and not justification:
            flash('Debes justificar por qué el control no es aplicable.','error')
        else:
            db.execute('UPDATE controls SET applicable=?,applicability_justification=?,owner=?,implementation_status=?,implementation_notes=?,evidence=?,reviewed_at=? WHERE id=?',
             (applicable_value,justification,request.form.get('owner','').strip(),request.form.get('implementation_status','No iniciado'),request.form.get('implementation_notes','').strip(),request.form.get('evidence','').strip(),date.today().isoformat(),control_id))
            audit('control',control_id,'soa_update',f"{c['code']} applicability={applicable_value}"); db.commit(); flash('Control de la SoA actualizado.','success'); return redirect(url_for('soa'))
    return render_template('soa_control_form.html',title=f"Editar {c['code']}",control=c)

@app.route('/reports/soa.csv')
@role_required('admin','gestor','consulta')
def export_soa():
    rows=get_db().execute('SELECT * FROM controls ORDER BY code').fetchall(); output=io.StringIO(); output.write('\ufeff'); w=csv.writer(output,delimiter=';')
    w.writerow(['Código','Categoría','Control','Aplicabilidad','Justificación exclusión','Responsable','Estado implementación','Notas','Evidencia','Última revisión'])
    for c in rows: w.writerow([c['code'],c['category'],c['title'],{None:'Pendiente',1:'Aplicable',0:'No aplicable'}[c['applicable']],c['applicability_justification'],c['owner'],c['implementation_status'],c['implementation_notes'],c['evidence'],c['reviewed_at']])
    return Response(output.getvalue(),mimetype='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename=declaracion_aplicabilidad.csv'})

@app.route('/methodology')
@role_required('admin','gestor','consulta')
def methodology():
    return render_template('methodology.html', title='Metodología y criterios')

@app.route('/health')
def health(): return {'status':'ok','application':'sgsi-riesgos'}

with app.app_context(): init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT','8080')))
