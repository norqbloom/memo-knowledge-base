(() => {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;

  const editorTab = document.querySelector('[data-editor-tab="edit"]');
  const previewTab = document.querySelector('[data-editor-tab="preview"]');
  const editPane = document.querySelector('#edit-pane');
  const previewPane = document.querySelector('#preview-pane');
  const textarea = document.querySelector('#content_md');

  if (editorTab && previewTab && editPane && previewPane && textarea && csrfToken) {
    const selectTab = (active) => {
      const showPreview = active === 'preview';
      editorTab.setAttribute('aria-selected', String(!showPreview));
      previewTab.setAttribute('aria-selected', String(showPreview));
      editPane.hidden = showPreview;
      previewPane.hidden = !showPreview;
    };

    editorTab.addEventListener('click', () => selectTab('edit'));
    previewTab.addEventListener('click', async () => {
      const editorHeight = textarea.getBoundingClientRect().height;
      if (editorHeight > 0) {
        previewPane.style.height = `${editorHeight}px`;
        previewPane.style.minHeight = `${editorHeight}px`;
      }
      selectTab('preview');
      previewPane.textContent = '読み込み中…';
      try {
        const response = await fetch('/editor/preview', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
          },
          body: JSON.stringify({ content_md: textarea.value }),
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'プレビューを生成できませんでした。');
        previewPane.innerHTML = result.html || '<p>本文がありません。</p>';
      } catch (error) {
        previewPane.textContent = error.message;
      }
    });
  }

  const picker = document.querySelector('[data-tag-picker]');
  if (!picker) return;

  const searchInput = picker.querySelector('#tag-search');
  const hiddenInput = picker.querySelector('#tags_json');
  const selectedContainer = picker.querySelector('[data-selected-tags]');
  const suggestions = picker.querySelector('#tag-suggestions');
  let selected = [];
  let searchSequence = 0;

  try {
    selected = JSON.parse(hiddenInput.value);
  } catch (_error) {
    selected = [];
  }

  const normalize = (value) => value.replace(/\s+/g, ' ').trim();
  const hasTag = (value) => selected.some((tag) => tag.toLocaleLowerCase() === value.toLocaleLowerCase());

  const sync = () => {
    hiddenInput.value = JSON.stringify(selected);
    selectedContainer.replaceChildren();
    selected.forEach((tag) => {
      const chip = document.createElement('span');
      chip.className = 'tag-chip';
      chip.textContent = tag;
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.setAttribute('aria-label', `${tag}を削除`);
      remove.textContent = '×';
      remove.addEventListener('click', () => {
        selected = selected.filter((item) => item !== tag);
        sync();
      });
      chip.append(remove);
      selectedContainer.append(chip);
    });
  };

  const addTag = (rawValue) => {
    const value = normalize(rawValue);
    if (!value || value.length > 30 || value.includes(',') || selected.length >= 10 || hasTag(value)) return;
    selected.push(value);
    searchInput.value = '';
    suggestions.hidden = true;
    sync();
  };

  const addSuggestion = (label, value, isNew = false) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.setAttribute('role', 'option');
    button.textContent = isNew ? `「${label}」を追加` : label;
    button.addEventListener('click', () => addTag(value));
    suggestions.append(button);
  };

  const searchTags = async () => {
    const query = normalize(searchInput.value);
    const sequence = ++searchSequence;
    suggestions.replaceChildren();
    if (!query) {
      suggestions.hidden = true;
      return;
    }
    try {
      const response = await fetch(`/api/tags?q=${encodeURIComponent(query)}`);
      const result = await response.json();
      if (sequence !== searchSequence) return;
      const candidates = (result.tags || []).filter((tag) => !hasTag(tag));
      candidates.forEach((tag) => addSuggestion(tag, tag));
      if (!hasTag(query) && !candidates.some((tag) => tag.toLocaleLowerCase() === query.toLocaleLowerCase())) {
        addSuggestion(query, query, true);
      }
      suggestions.hidden = suggestions.childElementCount === 0;
    } catch (_error) {
      suggestions.hidden = true;
    }
  };

  searchInput.addEventListener('input', searchTags);
  searchInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      addTag(searchInput.value);
    }
    if (event.key === 'Escape') suggestions.hidden = true;
  });
  searchInput.addEventListener('blur', () => window.setTimeout(() => { suggestions.hidden = true; }, 150));
  sync();
})();
