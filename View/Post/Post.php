<section id="section-post" class="page">
    <h1 class="page__title"><?= htmlspecialchars($post->getTitle()) ?></h1>

    <div class="page-container">
        <p class="post-chapo"><?= htmlspecialchars($post->getContent()) ?></p>
        <img src='./Uploads/<?= htmlspecialchars($post->getImage()) ?>' alt='<?= htmlspecialchars($post->getImage()) ?>' width='300px'>
        <p class="post-date">Dernière modification: <span><?= $post->getLastModificationDate() ?></span></p>

        <div class="comment-container">
            <?php foreach($comments as $comment){ ?>
                <div class="comment">
                    <p class="comment-content"><?= htmlspecialchars($comment->getContent()) ?></p>
                    <p class="comment-date">publié le: <span><?= htmlspecialchars($comment->getPublicationDate()) ?></span></p>
                </div>
            <?php } ?>

            <form method="POST" class="form__container">
                <h2 class="form__title">Ajouter un commentaire</h2>
                <div class="form__control">
                    <label class="form__label" for="content"><?= htmlspecialchars($form->fields['content']['label']) ?></label>
                    <textarea class="form__input" name="content" type="text" id="content" value="<?= htmlspecialchars($form->fields['content']['value']) ?>"></textarea>
                    <?php if(count($form->fields['content']['errors']) > 0) { ?>
                        <?php foreach($form->fields['content']['errors'] as $error) { ?>
                            <span class="alert alert-danger"><?= htmlspecialchars($error) ?></span>
                        <?php } ?>
                    <?php } ?>
                </div>
                <button type="submit" class="btn btn-primary" name="submit">Ajouter</button>
            </form>
        </div>
    </div>
</section>