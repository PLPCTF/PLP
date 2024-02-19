## Imports

import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_login import LoginManager, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, validators, TextAreaField, IntegerField, SelectMultipleField, widgets
from wtforms.widgets import ListWidget, CheckboxInput
from wtforms.validators import ValidationError, DataRequired
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
from wtforms import StringField, PasswordField, SubmitField, SelectField

## Configuration

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'votre_clé_secrète'


app.config['MAIL_SERVER'] = 'smtp.example.com'  # Utilisez votre serveur SMTP
app.config['MAIL_PORT'] = 587  # Utilisez le port approprié pour votre serveur SMTP
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'your_username'
app.config['MAIL_PASSWORD'] = 'your_password'

mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = 'connexion'
login_manager.login_message_category = 'info'

db = SQLAlchemy(app)
migrate = Migrate(app, db)


## Classes

class FormulaireInscription(FlaskForm):
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    classe = StringField('Classe')
    nom = StringField('Nom', validators=[validators.DataRequired()])
    prenom = StringField('Prénom', validators=[validators.DataRequired()])
    nom_utilisateur = StringField('Nom d\'utilisateur', validators=[validators.DataRequired(), validators.Length(min=4, max=20)])
    mot_de_passe = PasswordField('Mot de passe', validators=[validators.DataRequired(), validators.Length(min=8)])
    confirmer_mot_de_passe = PasswordField('Confirmer le mot de passe', validators=[validators.DataRequired(), validators.EqualTo('mot_de_passe', message='Les mots de passe doivent correspondre.')])
    inscription = SubmitField('S\'inscrire')

class FormulaireConnexion(FlaskForm):
    nom_utilisateur = StringField('Nom d\'utilisateur', validators=[validators.DataRequired()])
    mot_de_passe = PasswordField('Mot de passe', validators=[validators.DataRequired()])
    connexion = SubmitField('Se connecter')

class FormulaireMotDePasseOublie(FlaskForm):
    email = StringField('Adresse e-mail', validators=[validators.DataRequired(), validators.Email()])
    soumettre = SubmitField('Envoyer les instructions')

class FormulaireReinitialiserMotDePasse(FlaskForm):
    nouveau_mot_de_passe = PasswordField('Nouveau mot de passe', validators=[validators.DataRequired(), validators.Length(min=8)])
    confirmation_mot_de_passe = PasswordField('Confirmer le nouveau mot de passe', validators=[validators.EqualTo('nouveau_mot_de_passe', message='Les mots de passe doivent correspondre.')])
    soumettre = SubmitField('Réinitialiser le mot de passe')

class FormulaireProfil(FlaskForm):
    email = StringField('Email', validators=[validators.Optional(), validators.Email()])
    classe = StringField('Classe', validators=[validators.Optional()])
    nom = StringField('Nom', validators=[validators.Optional()])
    prenom = StringField('Prénom', validators=[validators.Optional()])
    nom_utilisateur = StringField('Nom d\'utilisateur', validators=[validators.Optional(), validators.Length(min=4, max=20)])
    mot_de_passe_actuel = PasswordField('Mot de passe actuel', validators=[validators.DataRequired()])
    nouveau_mot_de_passe = PasswordField('Nouveau mot de passe', validators=[validators.Length(min=8)])
    confirmation_mot_de_passe = PasswordField('Confirmer le nouveau mot de passe', validators=[validators.EqualTo('nouveau_mot_de_passe', message='Les mots de passe doivent correspondre.')])
    sauvegarder_modifications = SubmitField('Sauvegarder les modifications')

# Table de jointure pour les cours suivis par l'utilisateur
utilisateur_cours = db.Table('utilisateur_cours',
    db.Column('utilisateur_uid', db.Integer, db.ForeignKey('utilisateur.uid_utilisateur'), primary_key=True),
    db.Column('cours_uid', db.Integer, db.ForeignKey('cours.uid_cours'), primary_key=True)
)

# Table de jointure pour les challenges validés par l'utilisateur
utilisateur_challenge = db.Table('utilisateur_challenge',
    db.Column('utilisateur_uid', db.Integer, db.ForeignKey('utilisateur.uid_utilisateur'), primary_key=True),
    db.Column('challenge_uid', db.Integer, db.ForeignKey('challenge.uid_challenge'), primary_key=True)
)

challenges_cours = db.Table('challenges_cours',
    db.Column('challenge_id', db.Integer, db.ForeignKey('challenge.uid_challenge'), primary_key=True),
    db.Column('cours_id', db.Integer, db.ForeignKey('cours.uid_cours'), primary_key=True)
)

class Utilisateur(db.Model):
    uid_utilisateur = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    classe = db.Column(db.String(50))
    nom = db.Column(db.String(50), nullable=False)
    prenom = db.Column(db.String(50), nullable=False)
    nom_utilisateur = db.Column(db.String(20), unique=True, nullable=False)
    mot_de_passe = db.Column(db.String(60), nullable=False)
    token_de_reinitialisation = db.Column(db.String(50))
    score = db.Column(db.Integer, default=0)
    role = db.Column(db.Integer, default=1)  # 0 = banni, 1 = utilisateur, 2 = administrateur

    # Relation avec les cours et les challenges
    cours_suivis = db.relationship('Cours', secondary='utilisateur_cours', backref='utilisateurs', lazy='dynamic')
    challenges_valides = db.relationship('Challenge', secondary='utilisateur_challenge', backref='utilisateurs', lazy='dynamic')

    # Les méthodes pour l'intégration de Flask-Login
    def get_id(self):
        return str(self.uid_utilisateur)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False


class FormulaireCours(FlaskForm):
    titre_cours = StringField('Titre', validators=[DataRequired()])
    description_cours = TextAreaField('Description', validators=[DataRequired()])
    categorie_cours = StringField('Catégorie', validators=[DataRequired()])
    contenu = TextAreaField('Contenu', validators=[DataRequired()])
    submit = SubmitField('Créer Cours')

class Cours(db.Model):
    uid_cours = db.Column(db.Integer, primary_key=True)
    titre_cours = db.Column(db.String(100), nullable=False)
    description_cours = db.Column(db.Text, nullable=False)
    categorie_cours = db.Column(db.String(100), nullable=False)
    contenu = db.Column(db.Text, nullable=False)


class FormulaireChallenge(FlaskForm):
    titre_challenge = StringField('Titre', validators=[DataRequired()])
    description_challenge = TextAreaField('Description', validators=[DataRequired()])
    categorie_challenge = StringField('Catégorie', validators=[DataRequired()])
    cours_associes = SelectMultipleField('Cours Associés', choices=[], widget=ListWidget(prefix_label=False), option_widget=CheckboxInput(), coerce=int)
    indice = TextAreaField('Indice', validators=[DataRequired()])
    value = IntegerField('Valeur', validators=[DataRequired()])
    lien_ctfd = StringField('Lien CTFD', validators=[DataRequired()])
    flag = StringField('Flag', validators=[DataRequired()])
    submit = SubmitField('Ajouter Challenge')

class Challenge(db.Model):
    uid_challenge = db.Column(db.Integer, primary_key=True)
    titre_challenge = db.Column(db.String(100), nullable=False)
    categorie_challenge = db.Column(db.String(100), nullable=False)
    description_challenge = db.Column(db.Text, nullable=False)
    indice = db.Column(db.String(255))
    flag = db.Column(db.String(100), nullable=False)
    lien_ctfd = db.Column(db.String(100), nullable=False)
    value = db.Column(db.Integer, nullable=False)
    cours = db.relationship('Cours', secondary=challenges_cours, backref=db.backref('challenges', lazy=True))

class FormulaireDemandeInscription(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    classe = StringField('Classe')
    nom = StringField('Nom', validators=[DataRequired()])
    prenom = StringField('Prénom', validators=[DataRequired()])
    nom_utilisateur = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    mot_de_passe = StringField('Mot de passe', validators=[DataRequired()])
    role_demande = SelectField('Rôle', choices=[('1', 'Utilisateur'), ('2', 'Administrateur')], validators=[DataRequired()])
    valider = SubmitField('Valider')
    rejeter = SubmitField('Rejeter')

class DemandeInscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    classe = db.Column(db.String(50))
    nom = db.Column(db.String(50), nullable=False)
    prenom = db.Column(db.String(50), nullable=False)
    nom_utilisateur = db.Column(db.String(20), unique=True, nullable=False)
    mot_de_passe = db.Column(db.String(64), nullable=False)  # Stockage du mot de passe haché
    role = db.Column(db.Integer, default=1)  # Par défaut, utilisateur lambda
    

class ValidationDemandeForm(FlaskForm):
    role = SelectField('Rôle', choices=[('1', 'Utilisateur'), ('2', 'Administrateur')])

# Fonction pour vérifier si l'utilisateur est un administrateur
def est_admin(utilisateur):
    return utilisateur.role == 2

# Fonction pour vérifier si l'utilisateur est un utilisateur lambda
def est_lambda(utilisateur):
    return utilisateur.role == 1



# Décorateur pour restreindre l'accès aux administrateurs
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        utilisateur = Utilisateur.query.get(session['utilisateur_uid_utilisateur'])    
        if not est_admin(utilisateur):  # Assurez-vous que cette fonction renvoie True si l'utilisateur est un admin
            return redirect(url_for('accueil'))  # Redirige vers la page lambda si l'utilisateur n'est pas un admin
        return f(*args, **kwargs)
    return decorated_function



    

@login_manager.user_loader
def load_user(user_id):
    return Utilisateur.query.get(int(user_id))


def validate_nom_utilisateur(self, field):
    if current_user.is_authenticated and field.data != current_user.nom_utilisateur:
        # Si l'utilisateur a fourni un nouveau nom d'utilisateur, vérifiez s'il est déjà pris
        if Utilisateur.query.filter_by(nom_utilisateur=field.data).first():
            raise ValidationError('Ce nom d\'utilisateur est déjà pris.')

def validate_email(self, field):
    if current_user.is_authenticated and field.data != current_user.email:
        # Si l'utilisateur a fourni une adresse mail, vérifiez si elle est déjà prise
        if Utilisateur.query.filter_by(email=field.data).first():
            raise ValidationError('Cette adresse mail est déjà prise.')

def create_app():
    with app.app_context():
        db.create_all()


## Routes

@app.route('/', methods=['GET', 'POST'])
def connexion():
    if 'utilisateur_uid_utilisateur' in session:
        flash('Vous êtes déjà connecté.', 'info')
        return redirect(url_for('accueil'))

    form = FormulaireConnexion()
    if form.validate_on_submit():
        utilisateur = Utilisateur.query.filter_by(nom_utilisateur=form.nom_utilisateur.data).first()
        if utilisateur and check_password_hash(utilisateur.mot_de_passe, form.mot_de_passe.data):
            session['utilisateur_uid_utilisateur'] = utilisateur.uid_utilisateur
            flash('Connexion réussie !', 'success')
            return redirect(url_for('accueil'))
        else:
            flash('Échec de la connexion. Vérifiez vos informations.', 'danger')

    return render_template('connexion.html', form=form)

@app.route('/accueil')
def accueil():
    if 'utilisateur_uid_utilisateur' not in session:
        return redirect(url_for('connexion'))
    return render_template('accueil.html')

import hashlib

@app.route('/inscription', methods=['GET', 'POST'])
def inscription():
    form = FormulaireInscription()
    if form.validate_on_submit():
        # Créer une nouvelle demande d'inscription en attente de validation par l'administrateur
        demande = DemandeInscription(
            email=form.email.data,
            classe=form.classe.data,
            nom=form.nom.data,
            prenom=form.prenom.data,
            nom_utilisateur=form.nom_utilisateur.data,
            mot_de_passe = generate_password_hash(form.mot_de_passe.data, method='pbkdf2:sha256')
        )
        db.session.add(demande)
        db.session.commit()
        flash('Votre demande d\'inscription a été envoyée à l\'administrateur pour validation.', 'success')
        return redirect(url_for('connexion'))
    return render_template('inscription.html', form=form)


def generate_token(utilisateur):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(utilisateur.uid_utilisateur, salt=app.config['SECURITY_PASSWORD_SALT'])

def validate_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        utilisateur_uid_utilisateur = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
        return Utilisateur.query.get(utilisateur_uid_utilisateur)
    except:
        return None

def envoyer_email_reinitialisation(destinataire, token):
    sujet = 'Réinitialisation de mot de passe'
    corps = f'Cliquez sur le lien suivant pour réinitialiser votre mot de passe : {url_for("reinitialiser_mot_de_passe", token=token, _external=True)}'
    message = Message(sujet, recipients=[destinataire], body=corps)
    mail.send(message)


@app.route('/mot-de-passe-oublie', methods=['GET', 'POST'])
def mot_de_passe_oublie():
    if 'utilisateur_uid_utilisateur' in session:
        flash('Vous êtes déjà connecté.', 'info')
        return redirect(url_for('accueil'))

    form = FormulaireMotDePasseOublie()
    if form.validate_on_submit():
        utilisateur = Utilisateur.query.filter_by(email=form.email.data).first()

        if utilisateur:
            # Générer un jeton de réinitialisation de mot de passe et envoyer un e-mail avec un lien pour réinitialiser le mot de passe
            token = generate_token(utilisateur)
            envoyer_email_reinitialisation(utilisateur.email, token)

            flash('Un e-mail avec des instructions de réinitialisation de mot de passe a été envoyé.', 'info')
            return redirect(url_for('connexion'))
        else:
            flash('Aucun compte associé à cette adresse e-mail.', 'danger')

    return render_template('mot_de_passe_oublie.html', form=form)




@app.route('/valider_demande_inscription/<int:demande_id>', methods=['POST'])
def valider_demande_inscription(demande_id):
    demande = DemandeInscription.query.get_or_404(demande_id)
    
    if request.method == 'POST':
        role_demande = request.form.get('role_demande')  # Récupérer le rôle choisi par l'administrateur
        if role_demande not in ['1', '2']:  # Vérifier si le rôle est valide
            flash('Veuillez sélectionner un rôle valide.', 'error')
            return redirect(url_for('valider_demande_inscription'))

        utilisateur = Utilisateur(
            email=demande.email,
            classe=demande.classe,
            nom=demande.nom,
            prenom=demande.prenom,
            nom_utilisateur=demande.nom_utilisateur,
            mot_de_passe=demande.mot_de_passe,
            role=int(role_demande)  # Convertir le rôle en entier
        )
        db.session.add(utilisateur)
        db.session.delete(demande)
        db.session.commit()
        flash('La demande d\'inscription a été validée avec succès.', 'success')
        return redirect(url_for('demandes_inscription_admin'))

@app.route('/rejeter-demande-inscription/<int:demande_id>', methods=['POST'])
def rejeter_demande_inscription(demande_id):
    demande = DemandeInscription.query.get_or_404(demande_id)
    db.session.delete(demande)  # Supprimer la demande d'inscription rejetée
    db.session.commit()
    flash('La demande d\'inscription a été rejetée.', 'danger')
    return redirect(url_for('demandes_inscription_admin'))

@app.route('/demandes-inscription')
def demandes_inscription_admin():
    demandes = DemandeInscription.query.all()
    form = FormulaireDemandeInscription()  # Remplacez VotreFormulaireDeValidation par votre formulaire de validation
    return render_template('admin_demandes_inscription.html', demandes=demandes, form=form)

   
   

@app.route('/reinitialiser-mot-de-passe/<token>', methods=['GET', 'POST'])
def reinitialiser_mot_de_passe(token):
    utilisateur = validate_token(token)

    if not utilisateur:
        flash('Le lien de réinitialisation est invalide ou a expiré.', 'danger')
        return redirect(url_for('mot_de_passe_oublie'))

    form = FormulaireReinitialiserMotDePasse()

    if form.validate_on_submit():
        utilisateur.mot_de_passe = generate_password_hash(form.nouveau_mot_de_passe.data, method='pbkdf2:sha256')
        db.session.commit()

        flash('Le mot de passe a été réinitialisé avec succès. Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('connexion'))

    return render_template('reinitialiser_mot_de_passe.html', form=form)

@app.route('/profil', methods=['GET', 'POST'])
def profil():
    if 'utilisateur_uid_utilisateur' not in session:
        flash('Veuillez vous connecter pour accéder à votre profil.', 'warning')
        return redirect(url_for('connexion'))

    utilisateur = Utilisateur.query.get(session['utilisateur_uid_utilisateur'])
    form = FormulaireProfil(obj=utilisateur)

    if form.validate_on_submit():
        # Vérifier le mot de passe actuel
        if not check_password_hash(utilisateur.mot_de_passe, form.mot_de_passe_actuel.data):
            flash('Le mot de passe actuel est incorrect.', 'danger')
            return redirect(url_for('profil'))

        # Mettre à jour les informations de l'utilisateur
        utilisateur.email = form.email.data
        utilisateur.classe = form.classe.data
        utilisateur.nom = form.nom.data
        utilisateur.prenom = form.prenom.data
        utilisateur.nom_utilisateur = form.nom_utilisateur.data

        # Mettre à jour le mot de passe si un nouveau mot de passe est fourni
        if form.nouveau_mot_de_passe.data:
            utilisateur.mot_de_passe = generate_password_hash(form.nouveau_mot_de_passe.data, method='pbkdf2:sha256')

        # Sauvegarder les modifications dans la base de données
        db.session.commit()

        flash('Modifications sauvegardées avec succès.', 'success')
        return redirect(url_for('profil'))

    return render_template('profil.html', utilisateur=utilisateur, form=form)


## Cours

@app.route('/cours')
def afficher_cours():
    cours_list = Cours.query.all()  # Récupère tous les cours
    return render_template('cours.html', cours_list=cours_list)

@app.route('/cours/creer-cours', methods=['GET', 'POST'])
def creer_cours():
    form = FormulaireCours()
    if form.validate_on_submit():
        nouveau_cours = Cours(titre_cours=form.titre_cours.data,
                              description_cours=form.description_cours.data,
                              categorie_cours=form.categorie_cours.data,
                              contenu=form.contenu.data)
        db.session.add(nouveau_cours)
        db.session.commit()
        flash('Le cours a été créé avec succès.', 'success')
        return redirect(url_for('afficher_cours'))
    return render_template('creer_cours.html', form=form, est_modification=False)

@app.route('/cours/modifier/<int:uid_cours>', methods=['GET', 'POST'])
def modifier_cours(uid_cours):
    cours = Cours.query.get_or_404(uid_cours)
    form = FormulaireCours(obj=cours)
    if form.validate_on_submit():
        cours.titre_cours = form.titre_cours.data
        cours.description_cours = form.description_cours.data
        cours.categorie_cours = form.categorie_cours.data
        cours.contenu = form.contenu.data
        db.session.commit()
        flash('Le cours a été mis à jour avec succès.', 'success')
        return redirect(url_for('detail_cours', uid_cours=uid_cours))
    return render_template('creer_cours.html', form=form, cours=cours, est_modification=True)

@app.route('/cours/supprimer/<int:uid_cours>', methods=['POST'])
def supprimer_cours(uid_cours):
    cours = Cours.query.get_or_404(uid_cours)
    db.session.delete(cours)
    db.session.commit()
    flash('Le cours a été supprimé.', 'success')
    return redirect(url_for('afficher_cours'))

@app.route('/cours/<int:uid_cours>')
def detail_cours(uid_cours):
    cours = Cours.query.get_or_404(uid_cours)  # Récupère le cours ou renvoie une erreur 404
    return render_template('detail_cours.html', cours=cours)


## Challenges

@app.route('/challenges')
def afficher_challenges():
    challenges_list = Challenge.query.all()
    utilisateur = Utilisateur.query.get(session['utilisateur_uid_utilisateur']) 
    est_administrateur = est_admin(Utilisateur)  # Appel à votre fonction pour vérifier si l'utilisateur est un administrateur
    return render_template('challenges.html', challenges_list=challenges_list,  est_administrateur=est_administrateur)

@app.route('/challenges/ajouter-challenge', methods=['GET', 'POST'])
@admin_required
def ajouter_challenge():
    utilisateur = Utilisateur.query.get(session['utilisateur_uid_utilisateur'])
    form = FormulaireChallenge()
    # Récupérer tous les cours de la base de données et les trier par titre
    cours_list = Cours.query.order_by(Cours.titre_cours).all()
    
    # Passer la liste triée à votre template
    if form.validate_on_submit():
        nouveau_challenge = Challenge(
            titre_challenge=form.titre_challenge.data,
            description_challenge=form.description_challenge.data,
            categorie_challenge=form.categorie_challenge.data,
            indice=form.indice.data,
            value=form.value.data,
            lien_ctfd=form.lien_ctfd.data,
            flag=form.flag.data,
            cours_id=form.cours_id.data
        )
        db.session.add(nouveau_challenge)
        db.session.commit()
        flash('Le challenge a été ajouté avec succès.', 'success')
        return redirect(url_for('afficher_challenges'))
    return render_template('ajouter_challenge.html', form=form, cours_list=cours_list)

@app.route('/challenges/modifier/<int:uid_challenge>', methods=['GET', 'POST'])
def modifier_challenge(uid_challenge):
    challenge = Challenge.query.get_or_404(uid_challenge)
    form = FormulaireChallenge(obj=challenge)
    if form.validate_on_submit():
        challenge.titre_challenge = form.titre_challenge.data
        challenge.categorie_challenge=form.categorie_challenge.data
        challenge.description_challenge=form.description_challenge.data
        challenge.indice=form.indice.data
        challenge.value=form.value.data
        challenge.lien_ctfd=form.lien_ctfd.data
        challenge.flag=form.flag.data
        db.session.commit()
        flash('Le challenge a été mis à jour avec succès.', 'success')
        return redirect(url_for('detail_challenge', uid_challenge=uid_challenge))
    return render_template('ajouter_challenge.html', form=form, challenge=challenge, est_modification=True)

@app.route('/challenges/supprimer/<int:uid_challenge>', methods=['POST'])
def supprimer_challenge(uid_challenge):
    challenge = Challenge.query.get_or_404(uid_challenge)
    db.session.delete(challenge)
    db.session.commit()
    flash('Le challenge a été supprimé.', 'success')
    return redirect(url_for('afficher_challenges'))

@app.route('/challenges/<int:uid_challenge>')
def detail_challenge(uid_challenge):
    challenge = Challenge.query.get_or_404(uid_challenge)
    return render_template('detail_challenge.html', challenge=challenge)


@app.route('/deconnexion')
def deconnexion():
    session.clear()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('connexion'))

##dashboard
@app.route('/utilisateurs')
def page_utilisateur():
    utilisateurs = Utilisateur.query.all()
    return render_template('utilisateurs.html', utilisateurs=utilisateurs)

@app.route('/dashboard')
def dashboard():
    # Statistiques en dur pour tester
    user_stats = {
        'total_points': 750,
        'category_progress': {
            'Web': {'completed_challenges': 1, 'total_challenges': 3},
            'Brut force': {'completed_challenges': 4, 'total_challenges': 4},
            'SQL': {'completed_challenges': 2, 'total_challenges': 5},
            'Sécurité Applicative': {'completed_challenges': 3, 'total_challenges': 6},
            'Réseau': {'completed_challenges': 0, 'total_challenges': 2}
        }
    }

    # Calculez le pourcentage de progression pour chaque catégorie
    category_progress_percentages = {}
    points_gained_per_category = {}
    for category, progress in user_stats['category_progress'].items():
        completed = progress['completed_challenges']
        total = progress['total_challenges']
        if total != 0:
            progress_percentage = (completed / total) * 100
        else:
            progress_percentage = 0
        category_progress_percentages[category] = progress_percentage
        points_gained_per_category[category] = completed * 100  # Suppose que chaque challenge vaut 100 points

    return render_template('dashboard.html', user_stats=user_stats, category_progress_percentages=category_progress_percentages, points_gained_per_category=points_gained_per_category)
## Main
if __name__ == '__main__':
    create_app()
    app.run(debug=True)
