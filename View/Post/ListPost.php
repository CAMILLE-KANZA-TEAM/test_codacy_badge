<section id="section-listpost" class="page">
    <h1 class="page__title">Liste des articles</h1>

    <div class="card-container">
        <?php foreach($posts as $post){ ?>
            <div class="card">
                <p class="card-title"><?= htmlspecialchars($post->getTitle()) ?></p>
                <p class="card-chapo"><?= htmlspecialchars($post->getChapo()) ?></p>
                <p class="card-date">Dernière modification: <span><?= htmlspecialchars($post->getLastModificationDate()) ?></span></p>
                <a href="/post?id=<?= htmlspecialchars($post->getId()) ?>" class="btn btn-primary">En savoir plus</a>
            </div>
        <?php } ?>
    </div>
</section>