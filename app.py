## Imports

import secrets
import os

from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, flash, session, request, send_from_directory
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import LoginManager, current_user, login_required, login_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, validators, TextAreaField, IntegerField, SelectMultipleField, widgets, SelectField
from wtforms.widgets import ListWidget, CheckboxInput
from wtforms.validators import ValidationError, DataRequired
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
from wtforms.ext.sqlalchemy.fields import QuerySelectField
from sqlalchemy.sql import func
from collections import defaultdict


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


## Formulaires

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

class FormulaireInscription(FlaskForm):
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    classe = SelectField('Classe', choices=[('1A', '1A'), ('2A', '2A'), ('3A', '3A'), ('4A', '4A'), ('5A', '5A'), ('license', 'License'), ('master', 'Master'), ('professeur', 'Professeur')], validators=[DataRequired()])
    nom = StringField('Nom', validators=[validators.DataRequired()])
    prenom = StringField('Prénom', validators=[validators.DataRequired()])
    nom_utilisateur = StringField('Nom d\'utilisateur', validators=[validators.DataRequired(), validators.Length(min=4, max=20)])
    mot_de_passe = PasswordField('Mot de passe', validators=[validators.DataRequired(), validators.Length(min=8)])
    confirmer_mot_de_passe = PasswordField('Confirmer le mot de passe', validators=[validators.DataRequired(), validators.EqualTo('mot_de_passe', message='Les mots de passe doivent correspondre.')])
    inscription = SubmitField('S\'inscrire')

    def validate_nom_utilisateur(self, nom_utilisateur):
        if Utilisateur.query.filter_by(nom_utilisateur=nom_utilisateur.data).first():
            raise ValidationError('Ce nom d\'utilisateur est déjà pris.')

    def validate_email(self, email):
        if Utilisateur.query.filter_by(email=email.data).first():
            raise ValidationError('Cette adresse mail est déjà prise.')

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

class FormulaireCours(FlaskForm):
    titre_cours = StringField('Titre', validators=[DataRequired()])
    categorie_cours = QuerySelectField('Catégorie du cours', query_factory=lambda: Categorie.query.all(), allow_blank=True, get_label='nom')
    nouvelle_categorie = StringField('Nouvelle catégorie')
    description_cours = TextAreaField('Description', validators=[DataRequired()])
    lien = StringField('Lien de téléchargement')
    fichier = FileField('Fichier du cours')
    submit = SubmitField('Créer Cours')

class FormulaireChallenge(FlaskForm):
    titre_challenge = StringField('Titre', validators=[DataRequired()])
    description_challenge = TextAreaField('Description', validators=[DataRequired()])
    categorie_challenge = StringField('Catégorie', validators=[DataRequired()])
    cours_associe = SelectField('Cours Associé', coerce=int)
    indice = TextAreaField('Indice', validators=[DataRequired()])
    value = IntegerField('Valeur', validators=[DataRequired()])
    lien_ctfd = StringField('Lien CTFD', validators=[DataRequired()])
    flag = StringField('Flag', validators=[DataRequired()])
    submit = SubmitField('Ajouter Challenge')

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

class Categorie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(50), unique=True, nullable=False)

class Cours(db.Model):
    uid_cours = db.Column(db.Integer, primary_key=True)
    titre_cours = db.Column(db.String(100), nullable=False)
    categorie_cours = db.Column(db.String(100), nullable=False)
    description_cours = db.Column(db.Text, nullable=False)
    lien = db.Column(db.String(100), nullable=False)
    fichier = db.Column(db.String(100))  # Champ pour le fichier

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

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 2:
            flash("Vous n'avez pas les permissions pour accéder à cette page.", 'danger')
            return redirect(url_for('accueil'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(uid_utilisateur):
    return Utilisateur.query.get(int(uid_utilisateur))

def create_app():
    with app.app_context():
        db.create_all()


## Routes

@app.route('/', methods=['GET', 'POST'])
def connexion():
    if current_user.is_authenticated:
        flash('Vous êtes déjà connecté.', 'info')
        return redirect(url_for('accueil'))

    form = FormulaireConnexion()
    if form.validate_on_submit():
        utilisateur = Utilisateur.query.filter_by(nom_utilisateur=form.nom_utilisateur.data).first()
        if utilisateur and check_password_hash(utilisateur.mot_de_passe, form.mot_de_passe.data):
            login_user(utilisateur)
            flash('Connexion réussie !', 'success')
            return redirect(url_for('accueil'))
        else:
            flash('Échec de la connexion. Vérifiez vos informations.', 'danger')

    return render_template('connexion.html', form=form)

@app.route('/accueil')
def accueil():
    if not current_user.is_authenticated:
        return redirect(url_for('connexion'))
    return render_template('accueil.html')

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
        return Utilisateur.query.get(utilisateur.uid_utilisateur)
    except:
        return None

def envoyer_email_reinitialisation(destinataire, token):
    sujet = 'Réinitialisation de mot de passe'
    corps = f'Cliquez sur le lien suivant pour réinitialiser votre mot de passe : {url_for("reinitialiser_mot_de_passe", token=token, _external=True)}'
    message = Message(sujet, recipients=[destinataire], body=corps)
    mail.send(message)

@app.route('/mot-de-passe-oublie', methods=['GET', 'POST'])
def mot_de_passe_oublie():
    if current_user.is_authenticated:
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

@app.route('/valider_demande_inscription/<int:demande_id>', methods=['POST'])
@admin_required
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
@admin_required
def rejeter_demande_inscription(demande_id):
    demande = DemandeInscription.query.get_or_404(demande_id)
    db.session.delete(demande)  # Supprimer la demande d'inscription rejetée
    db.session.commit()
    flash('La demande d\'inscription a été rejetée.', 'danger')
    return redirect(url_for('demandes_inscription_admin'))

@app.route('/demandes-inscription')
@admin_required
def demandes_inscription_admin():
    demandes = DemandeInscription.query.all()
    form = FormulaireDemandeInscription()  # Remplacez VotreFormulaireDeValidation par votre formulaire de validation
    return render_template('admin_demandes_inscription.html', demandes=demandes, form=form)

@app.route('/profil', methods=['GET', 'POST'])
@login_required
def profil():
    if not current_user.is_authenticated:
        flash('Veuillez vous connecter pour accéder à votre profil.', 'warning')
        return redirect(url_for('connexion'))

    form = FormulaireProfil(obj=current_user)

    if form.validate_on_submit():
        # Vérifier le mot de passe actuel
        if not check_password_hash(current_user.mot_de_passe, form.mot_de_passe_actuel.data):
            flash('Le mot de passe actuel est incorrect.', 'danger')
            return redirect(url_for('profil'))

        # Mettre à jour les informations de l'utilisateur
        current_user.email = form.email.data
        current_user.classe = form.classe.data
        current_user.nom = form.nom.data
        current_user.prenom = form.prenom.data
        current_user.nom_utilisateur = form.nom_utilisateur.data

        # Mettre à jour le mot de passe si un nouveau mot de passe est fourni
        if form.nouveau_mot_de_passe.data:
            current_user.mot_de_passe = generate_password_hash(form.nouveau_mot_de_passe.data, method='pbkdf2:sha256')

        # Sauvegarder les modifications dans la base de données
        db.session.commit()

        flash('Modifications sauvegardées avec succès.', 'success')
        return redirect(url_for('profil'))

    return render_template('profil.html', utilisateur=current_user, form=form)

@app.route('/classement', methods=['GET', 'POST'])
@login_required
def classement():
    tri = request.args.get('tri', 'score')
    ordre = request.args.get('ordre', 'desc')
    recherche = request.args.get('recherche', '')

    if tri == 'score':
        if ordre == 'asc':
            utilisateurs = Utilisateur.query.filter(Utilisateur.nom_utilisateur.like(f"%{recherche}%")).order_by(Utilisateur.score.asc())
        else:
            utilisateurs = Utilisateur.query.filter(Utilisateur.nom_utilisateur.like(f"%{recherche}%")).order_by(Utilisateur.score.desc())
    else:
        if ordre == 'asc':
            utilisateurs = Utilisateur.query.filter(Utilisateur.nom_utilisateur.like(f"%{recherche}%")).order_by(Utilisateur.nom_utilisateur.asc())
        else:
            utilisateurs = Utilisateur.query.filter(Utilisateur.nom_utilisateur.like(f"%{recherche}%")).order_by(Utilisateur.nom_utilisateur.desc())

    return render_template('classement.html', utilisateurs=utilisateurs)


## Cours

@app.route('/cours')
@login_required
def afficher_cours():
    cours_list = Cours.query.all()  # Récupère tous les cours
    cours_par_categorie = defaultdict(list)
    for cours in cours_list:
        cours_par_categorie[cours.categorie_cours].append(cours)
    return render_template('cours.html', cours_par_categorie=cours_par_categorie)

@app.route('/telecharger/<path:filename>')
@login_required
def telecharger_fichier(filename):
    # Spécifiez le répertoire dans lequel se trouvent les fichiers à télécharger
    dossier_telechargements = 'D:/Windows/Data/INSA/5A/PLP/Site/static/cours'

    return send_from_directory(dossier_telechargements, filename)

@app.route('/cours/creer-cours', methods=['GET', 'POST'])
@admin_required
def creer_cours():
    form = FormulaireCours()

    if request.method == 'POST':
        if form.validate_on_submit():
            nouvelle_cat = form.nouvelle_categorie.data.strip()
            categorie_selectionnee = None

            if form.categorie_cours.data:
                # Si une catégorie existante est sélectionnée
                categorie_selectionnee = form.categorie_cours.data.nom.lower().strip()

            if nouvelle_cat:
                # Si une nouvelle catégorie est entrée
                nouvelle_cat = nouvelle_cat.lower().strip()
                # Vérifier si la nouvelle catégorie existe déjà
                categorie_existe = Categorie.query.filter_by(nom=nouvelle_cat).first()
                if categorie_existe:
                    # Si la nouvelle catégorie existe déjà, utiliser la catégorie existante
                    categorie_selectionnee = nouvelle_cat
                else:
                    # Si la nouvelle catégorie n'existe pas, l'ajouter à la base de données
                    nouvelle_categorie = Categorie(nom=nouvelle_cat)
                    db.session.add(nouvelle_categorie)
                    db.session.commit()
                    flash(f'La catégorie "{nouvelle_cat.capitalize()}" a été ajoutée avec succès.', 'success')
                    categorie_selectionnee = nouvelle_cat

            # Télécharger le fichier s'il est présent dans la requête
            fichier = None
            if 'fichier' in request.files:
                fichier = request.files['fichier']
                if fichier.filename != '':
                    # Spécifiez le répertoire où vous souhaitez enregistrer les fichiers téléchargés
                    dossier_uploads = 'D:/Windows/Data/INSA/5A/PLP/Site/static/cours'
                    # Assurez-vous que le répertoire existe, sinon créez-le
                    if not os.path.exists(dossier_uploads):
                        os.makedirs(dossier_uploads)
                    # Enregistrez le fichier dans le répertoire spécifié
                    chemin_fichier = os.path.join(dossier_uploads, fichier.filename)
                    fichier.save(chemin_fichier)

            # Créer le nouveau cours avec toutes les données du formulaire
            nouveau_cours = Cours(
                titre_cours=form.titre_cours.data,
                categorie_cours=categorie_selectionnee,
                description_cours=form.description_cours.data,
                fichier=fichier.filename if fichier else None,  # Enregistrer le nom du fichier dans la base de données
                lien=form.lien.data
            )
            db.session.add(nouveau_cours)
            db.session.commit()
            flash('Le cours a été créé avec succès.', 'success')
            return redirect(url_for('afficher_cours'))

    return render_template('creer_cours.html', form=form, est_modification=False)

@app.route('/cours/modifier/<int:uid_cours>', methods=['GET', 'POST'])
@admin_required
def modifier_cours(uid_cours):
    cours = Cours.query.get_or_404(uid_cours)
    form = FormulaireCours(obj=cours)
    if form.validate_on_submit():
        cours.titre_cours = form.titre_cours.data
        cours.categorie_cours = form.categorie_cours.data
        cours.description_cours = form.description_cours.data
        cours.lien = form.lien.data
        db.session.commit()
        flash('Le cours a été mis à jour avec succès.', 'success')
        return redirect(url_for('detail_cours', uid_cours=uid_cours))
    return render_template('creer_cours.html', form=form, cours=cours, est_modification=True)

@app.route('/cours/supprimer/<int:uid_cours>', methods=['POST'])
@admin_required
def supprimer_cours(uid_cours):
    cours = Cours.query.get_or_404(uid_cours)
    db.session.delete(cours)
    db.session.commit()
    flash('Le cours a été supprimé.', 'success')
    return redirect(url_for('afficher_cours'))

@app.route('/cours/<int:uid_cours>')
@login_required
def detail_cours(uid_cours):
    cours = Cours.query.get_or_404(uid_cours)  # Récupère le cours ou renvoie une erreur 404
    return render_template('detail_cours.html', cours=cours)

@app.route('/suivre_cours/<int:uid_cours>', methods=['POST'])
@login_required
def suivre_cours(uid_cours):
    cours = Cours.query.get(uid_cours)
    current_user.cours_suivis.append(cours)
    db.session.commit()
    flash('Vous suivez maintenant le cours.', 'success')
    return redirect(url_for('detail_cours', uid_cours=uid_cours))

@app.route('/ne_plus_suivre_cours/<int:uid_cours>', methods=['POST'])
@login_required
def ne_plus_suivre_cours(uid_cours):
    cours = Cours.query.get(uid_cours)
    if cours in current_user.cours_suivis:
        current_user.cours_suivis.remove(cours)
        db.session.commit()
        flash('Vous ne suivez plus le cours.', 'success')
    else:
        flash('Vous ne suivez pas ce cours.', 'warning')
    return redirect(url_for('detail_cours', uid_cours=uid_cours))

## Challenges

@app.route('/challenges')
@login_required
def afficher_challenges():
    challenges_list = Challenge.query.all()
    return render_template('challenges.html', challenges_list=challenges_list)

@app.route('/challenges/ajouter-challenge', methods=['GET', 'POST'])
@admin_required
def ajouter_challenge():
    form = FormulaireChallenge()
    form.cours_associe.choices = [(c.uid_cours, c.titre_cours) for c in Cours.query.order_by(Cours.titre_cours).all()]

    if form.validate_on_submit():
        nouveau_challenge = Challenge(
            titre_challenge=form.titre_challenge.data,
            categorie_challenge=form.categorie_challenge.data,
            description_challenge=form.description_challenge.data,
            indice=form.indice.data,
            value=form.value.data,
            lien_ctfd=form.lien_ctfd.data,
            flag=form.flag.data,
        )

        # Associer le cours sélectionné avec le challenge
        cours = Cours.query.get(form.cours_associe.data)
        if cours:
            nouveau_challenge.cours.append(cours)

        db.session.add(nouveau_challenge)
        db.session.commit()
        flash('Le challenge a été ajouté avec succès.', 'success')
        return redirect(url_for('afficher_challenges'))

    return render_template('ajouter_challenge.html', form=form)

@app.route('/challenges/modifier/<int:uid_challenge>', methods=['GET', 'POST'])
@admin_required
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
@admin_required
def supprimer_challenge(uid_challenge):
    challenge = Challenge.query.get_or_404(uid_challenge)
    db.session.delete(challenge)
    db.session.commit()
    flash('Le challenge a été supprimé.', 'success')
    return redirect(url_for('afficher_challenges'))

@app.route('/challenges/<int:uid_challenge>')
@login_required
def detail_challenge(uid_challenge):
    challenge = Challenge.query.get_or_404(uid_challenge)
    return render_template('detail_challenge.html', challenge=challenge)

@app.route('/challenges/verifier/<int:uid_challenge>', methods=['POST'])
@login_required
def verifier_flag(uid_challenge):
    challenge = Challenge.query.get_or_404(uid_challenge)
    flag_soumis = request.form['flag']

    if flag_soumis == challenge.flag:
        current_user.score += challenge.value
        current_user.challenges_valides.append(challenge)
        db.session.commit()
        flash('Flag correct, score mis à jour !', 'success')
    else:
        flash('Flag incorrect, veuillez réessayer.', 'danger')

    return redirect(url_for('detail_challenge', uid_challenge=uid_challenge))


## Dashboard

@app.route('/utilisateurs')
@admin_required
def page_utilisateur():
    utilisateurs = Utilisateur.query.all()
    return render_template('utilisateurs.html', utilisateurs=utilisateurs)

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    utilisateurs = Utilisateur.query.all()  # Récupérer tous les utilisateurs pour la liste déroulante
    utilisateur_id = request.args.get('utilisateur_id', type=int)  # Gardez l'ID en tant qu'entier si votre DB le stocke ainsi

    data_for_chart = {}
    completion_rate_for_chart = {}

    if utilisateur_id:
        # Points obtenus par l'utilisateur dans chaque catégorie
        points_obtenus = db.session.query(
            Challenge.categorie_challenge,
            func.sum(Challenge.value).label('points_obtenus')
        ).join(utilisateur_challenge, Challenge.uid_challenge == utilisateur_challenge.c.challenge_uid) \
         .filter(utilisateur_challenge.c.utilisateur_uid == utilisateur_id) \
         .group_by(Challenge.categorie_challenge) \
         .all()

        # Total des points possibles dans chaque catégorie
        total_points = db.session.query(
            Challenge.categorie_challenge,
            func.sum(Challenge.value).label('total_points')
        ).group_by(Challenge.categorie_challenge) \
         .all()

        # Convertir total_points en dictionnaire
        total_points_dict = {categorie: total_points for categorie, total_points in total_points}

        # Fusionner les données dans un format approprié pour le graphique
        data_for_chart = {
            categorie: {
                'points_obtenus': points,
                'total_points': total_points_dict.get(categorie, 0)
            } for categorie, points in points_obtenus
        }

        # Calculer le taux de complétion
        completion_rate_for_chart = {
            categorie: {
                'completion_rate': (points / total_points_dict.get(categorie, 1)) * 100
            } for categorie, points in points_obtenus
        }

    return render_template('dashboard.html', utilisateurs=utilisateurs, data_for_chart=data_for_chart, completion_rate_for_chart=completion_rate_for_chart, utilisateur_id=utilisateur_id)


@app.route('/deconnexion')
@login_required
def deconnexion():
    session.clear()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('connexion'))


## Main
if __name__ == '__main__':
    create_app()
    app.run(debug=True)
