<div class="error">
	<h1>Une erreur s'est produite</h1>
	<div class="error-message">Message : <?= htmlspecialchars($exception->getMessage()); ?></div>
	<div class="error-stack">Pile d'execution : <?= htmlspecialchars($exception->getTraceAsString()); ?></div>
    <?php if(method_exists($exception,"getMoreDetail")){ ?>
        <div class="error-detail"><?= htmlspecialchars($exception->getMoreDetail()); ?></div>
    <?php } ?>
</div>