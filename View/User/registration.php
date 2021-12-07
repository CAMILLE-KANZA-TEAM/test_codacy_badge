<div class="login__container">
	<form method="POST" class="login__form">
		<h2 class="form__title">Inscription</h2>
		<div class="form__control">
			<label class="form__label" for="pseudo"><?= htmlspecialchars($form->fields['pseudo']['label']) ?></label>
			<input class="form__input" name="pseudo" type="text" id="pseudo" value="<?= htmlspecialchars($form->fields['pseudo']['value']) ?>">
			<?php if(count($form->fields['pseudo']['errors']) > 0) { ?>
				<?php foreach($form->fields['pseudo']['errors'] as $error) { ?>
					<span class="alert alert-danger"><?= htmlspecialchars($error) ?></span>
				<?php } ?>
			<?php } ?>
		</div>
        <div class="form__control">
			<label class="form__label" for="email"><?= htmlspecialchars($form->fields['email']['label']) ?></label>
			<input class="form__input" name="email" type="text" id="email" value="<?= htmlspecialchars($form->fields['email']['value']) ?>">
			<?php if(count($form->fields['email']['errors']) > 0) { ?>
				<?php foreach($form->fields['email']['errors'] as $error) { ?>
					<span class="alert alert-danger"><?= htmlspecialchars($error) ?></span>
				<?php } ?>
			<?php } ?>
		</div>
		<div class="form__control">
			<label for="password" class="form__label"><?= htmlspecialchars($form->fields['password']['label']) ?></label>
			<input name="password" type="password" class="form__input" id="password" value="<?= htmlspecialchars($form->fields['password']['value']) ?>">
			<?php if(count($form->fields['password']['errors']) > 0) { ?>
				<?php foreach($form->fields['password']['errors'] as $error) { ?>
					<span class="alert alert-danger"><?= htmlspecialchars($error) ?></span>
				<?php } ?>
			<?php } ?>
		</div>
		<input name="_token" id="_token" type="hidden" value="<?php echo htmlspecialchars($_SESSION['_token']) ?>">
		<button type="submit" class="btn btn-primary" name="submit">Inscription</button>
	</form>
</div>