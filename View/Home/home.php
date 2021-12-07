<section id="section-accueil" class="page">
    <h1 class="page__title">Bienvenue sur mon blog</h1>
    <img class="image__profil" src="Media/Profil.jpg">
    <h3 class="title__profil">Aurélien <span>CORBLIN</span></h3>
    <p class="text__profil">Un jour tu connaîtra le succès, n'abandonne jamais !</p>

    <div class="infos__container">
        <div class="contact__form">
            <form action="/email/contact" method="POST" class="form__container">
		        <h2 class="form__title">Me contacter</h2>
                <div class="form__control">
                    <label class="form__label" for="prenom">Prénom</label>
			        <input class="form__input" name="prenom" type="text" id="prenom" required="true">
                </div>
                <div class="form__control">
                    <label class="form__label" for="nom">Nom</label>
			        <input class="form__input" name="nom" type="text" id="nom" required="true">
                </div>
                <div class="form__control">
                    <label class="form__label" for="email">Email</label>
			        <input class="form__input" name="email" type="email" id="email" required="true">
                </div>
                <div class="form__control">
                    <label class="form__label" for="message">Message</label>
			        <textarea class="form__input" name="message" id="message" required="true"></textarea>
                </div>
		        <button type="submit" class="btn btn-primary" name="submit">Envoyer</button>
            </form>
        </div>
        <div class="rs__container">
            <a class="pdf__link" href="./Files/CVAurelienCORBLIN.pdf" download="CV_Aurélien_CORBLIN">Télécharger mon cv !</a>
            <div class="rs__content">
                <a href="https://www.facebook.com/aurelien.corblin/"><img class="img-rs" src="./Files/facebook.svg"></a>
                <a href="https://www.linkedin.com/in/aur%C3%A9lien-corblin-3b5359181?lipi=urn%3Ali%3Apage%3Ad_flagship3_profile_view_base_contact_details%3BThaWX7ZnQGa35YhiyCEw8g%3D%3D"><img class="img-rs" src="./Files/linkedin.png"></a>
            </div>
            </div>
    </div>
</section>