<section id="section-postlist" class="page">
    <h1 class="page__title">Liste des commentaires</h1>

    <table>
        <thead>
            <tr>
                <th>Date</th>
                <th>Valide</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach($comments as $comment){ ?>
                <tr>
                    <td><?= htmlspecialchars($comment->getPublicationDate()) ?></td>
                    <td><?= htmlspecialchars($comment->getValid()) ?></td>
                    <td>
                        <?php if($comment->getValid() == "0"){ ?><a href="/admin/comment/valid?id=<?= htmlspecialchars($comment->getId()) ?>"><img class="table-img" src="../../Files/check_white_24dp.svg"></a><?php }else{ ?><a href="/admin/comment/devalid?id=<?= htmlspecialchars($comment->getId()) ?>"><img class="table-img" src="../../Files/clear_white_24dp.svg"></a><?php }; ?>
                        <a href="/admin/comment/delete?id=<?= htmlspecialchars($comment->getId()) ?>" onclick="return confirm('Etes-vous sûr de vouloir supprimer ce commentaire ?');"><img class="table-img" src="../../Files/delete_white_24dp.svg"></a>
                    </td>
                </tr>
            <?php } ?>
        </tbody>
    </table>
</section>