#!/usr/bin/env python3

import os
import tempfile
import zipfile
import io
import csv
import re
import sqlite3
import datetime
from itertools import combinations
from concurrent.futures import ThreadPoolExecutor, as_completed
import streamlit as st
import ppdeep
import pandas as pd


DB_PATH = "ssdeep_hashes.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            hash TEXT NOT NULL,
            tag TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def add_hash_to_db(filename, hash_value, tag):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    c.execute('INSERT INTO hashes (filename, hash, tag, timestamp) VALUES (?, ?, ?, ?)',
              (filename, hash_value, tag, timestamp))
    conn.commit()
    conn.close()

def get_all_hashes():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, filename, hash, tag, timestamp FROM hashes ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()
    return rows

def delete_hash_by_id(id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM hashes WHERE id = ?', (id,))
    conn.commit()
    conn.close()

def search_in_db(hash_value, threshold):
    all_hashes = get_all_hashes()
    results = []
    for db_id, db_filename, db_hash, db_tag, db_ts in all_hashes:
        sim = ppdeep.compare(hash_value, db_hash)
        if sim >= threshold:
            results.append((db_filename, db_hash, db_tag, sim))
    results.sort(key=lambda x: x[3], reverse=True)
    return results


def compute_hash_from_bytes(filename, content):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        h = ppdeep.hash_from_file(tmp_path)
        os.unlink(tmp_path)
        return (filename, h)
    except Exception as e:
        return (filename, None)

def process_uploaded_files_for_hash(uploaded_files):
    all_files = []
    for uf in uploaded_files:
        if uf.name.lower().endswith('.zip'):
            try:
                with zipfile.ZipFile(io.BytesIO(uf.read())) as zf:
                    for info in zf.infolist():
                        if not info.is_dir():
                            content = zf.read(info.filename)
                            all_files.append((info.filename, content))
            except Exception as e:
                st.error(f"Ошибка распаковки {uf.name}: {e}")
        else:
            all_files.append((uf.name, uf.read()))

    if not all_files:
        return {}

    hash_map = {}
    with st.status("Вычисление ssdeep-хэшей...", expanded=True) as status:
        progress_bar = st.progress(0, text="Обработка файлов...")
        total = len(all_files)
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_file = {
                executor.submit(compute_hash_from_bytes, name, content): (name, content)
                for name, content in all_files
            }
            for idx, future in enumerate(as_completed(future_to_file), 1):
                name, h = future.result()
                if h is not None:
                    hash_map[name] = h
                progress_bar.progress(idx / total, text=f"Обработано {idx}/{total}")
        status.update(label="Вычисление завершено", state="complete")
    return hash_map


from difflib import SequenceMatcher

def highlight_blocks_advanced(block1, block2, min_match=3, color="#ff0000"):
    matcher = SequenceMatcher(None, block1, block2)
    matches = matcher.get_matching_blocks()

    mask1 = [False] * len(block1)
    mask2 = [False] * len(block2)

    for match in matches:
        a, b, size = match
        if size >= min_match:
            for i in range(size):
                mask1[a + i] = True
                mask2[b + i] = True

    def apply_mask(text, mask):
        result = []
        opened = False
        for ch, flag in zip(text, mask):
            if flag and not opened:
                result.append(f'<span style="color:{color}; font-weight:bold;">')
                opened = True
            elif not flag and opened:
                result.append("</span>")
                opened = False
            result.append(ch)
        if opened:
            result.append("</span>")
        return ''.join(result)

    return apply_mask(block1, mask1), apply_mask(block2, mask2)

    def colorize(a, b):
        res = []
        for ch1, ch2 in zip(a, b):
            if ch1 == ch2 and ch1 != ' ':
                res.append(f'<span style="color:#ff0000; font-weight:bold;">{ch1}</span>')
            else:
                res.append(ch1)
        return ''.join(res)

    return colorize(b1, b2), colorize(b2, b1)

def find_clusters(file_list, hash_map, threshold):
    n = len(file_list)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[ry] = rx

    for i in range(n):
        for j in range(i + 1, n):
            h1 = hash_map[file_list[i]]
            h2 = hash_map[file_list[j]]
            if ppdeep.compare(h1, h2) >= threshold:
                union(i, j)

    clusters_dict = {}
    for i, f in enumerate(file_list):
        root = find(i)
        clusters_dict.setdefault(root, []).append(f)

    clusters = [sorted(clist) for clist in clusters_dict.values() if len(clist) >= 2]
    return clusters


def main():
    st.set_page_config(page_title="ssdeep Compare + База", layout="wide")
    
    st.markdown("""
<style>
    /* Общий фон и текст */
    .stApp {
        background-color: #0b1a2b;
        color: #c8d6e5;
        font-family: 'Segoe UI', 'Roboto', monospace;
    }
    /* Заголовки */
    h1, h2, h3, h4, h5, h6 {
        color: #7ec8e3;
        font-weight: 400;
        border-bottom: 1px solid #2a4a6b;
        padding-bottom: 5px;
    }
    /* Боковая панель */
    .css-1d391kg {
        background-color: #0d1f2d;
        border-right: 1px solid #2a4a6b;
    }
    /* Кнопки */
    .stButton button {
        background-color: #1a3348;
        color: #c8d6e5;
        border: 1px solid #2a5a7a;
        border-radius: 4px;
        font-family: 'Segoe UI', sans-serif;
        transition: all 0.2s ease;
    }
    .stButton button:hover {
        background-color: #2a5a7a;
        color: #ffffff;
        border-color: #4a8aba;
        box-shadow: 0 0 8px rgba(74, 138, 186, 0.3);
    }
    /* Чекбоксы */
    .stCheckbox label {
        color: #c8d6e5;
    }
    .stCheckbox input[type="checkbox"] {
        accent-color: #4a8aba;
    }
    /* Слайдеры */
    .stSlider label {
        color: #c8d6e5;
    }
    .stSlider .thumb {
        background-color: #4a8aba !important;
    }
    .stSlider .track {
        background-color: #2a4a6b !important;
    }
    .stSlider .track-0 {
        background-color: #4a8aba !important;
    }
    /* Поля ввода */
    .stTextInput input, .stNumberInput input {
        background-color: #0d1f2d;
        color: #c8d6e5;
        border: 1px solid #2a4a6b;
        border-radius: 4px;
        font-family: 'Consolas', monospace;
    }
    .stTextInput input:focus, .stNumberInput input:focus {
        border-color: #4a8aba;
        box-shadow: 0 0 8px rgba(74, 138, 186, 0.2);
    }
    /* Таблицы (dataframe) */
    .dataframe {
        background-color: #0d1f2d !important;
        color: #c8d6e5 !important;
        border: 1px solid #2a4a6b !important;
        font-size: 14px;
    }
    .dataframe thead tr th {
        background-color: #1a3348 !important;
        color: #7ec8e3 !important;
        border-bottom: 2px solid #2a5a7a !important;
        font-weight: 500;
    }
    .dataframe tbody tr:hover {
        background-color: #1a2f42 !important;
    }
    .dataframe tbody tr:nth-child(even) {
        background-color: #0f2233;
    }
    /* Expander */
    .streamlit-expanderHeader {
        background-color: #0d1f2d !important;
        color: #7ec8e3 !important;
        border: 1px solid #2a4a6b !important;
        border-radius: 4px;
        font-family: 'Segoe UI', sans-serif;
        font-weight: 500;
    }
    .streamlit-expanderHeader:hover {
        background-color: #1a3348 !important;
        border-color: #4a8aba !important;
    }
    .streamlit-expanderContent {
        background-color: #0b1a2b !important;
        border-left: 1px solid #2a4a6b !important;
        border-right: 1px solid #2a4a6b !important;
        border-bottom: 1px solid #2a4a6b !important;
        border-radius: 0 0 4px 4px;
        padding: 10px;
    }
    /* Код внутри */
    code {
        color: #7ec8e3 !important;
        background-color: #0d1f2d !important;
        padding: 2px 6px;
        border-radius: 3px;
        border: 1px solid #1a3348;
        font-family: 'Consolas', monospace;
        font-size: 13px;
    }
    /* Разделители */
    hr {
        border-color: #2a4a6b !important;
        border-width: 1px;
        margin: 20px 0;
    }
    /* Текст меток */
    label, .stMarkdown, .stText, .stAlert, .stInfo, .stSuccess, .stWarning, .stError {
        color: #c8d6e5 !important;
    }
    /* Сайдбар */
    .css-1d391kg .stMarkdown, .css-1d391kg label {
        color: #c8d6e5 !important;
    }
    .css-1d391kg .stMarkdown h1, .css-1d391kg .stMarkdown h2, .css-1d391kg .stMarkdown h3 {
        color: #7ec8e3 !important;
        border-bottom: 1px solid #2a4a6b;
    }
    /* Вкладки */
    .stTabs [data-baseweb="tab-list"] button [data-testid="stMarkdownContainer"] p {
        color: #7ec8e3 !important;
        font-weight: 500;
    }
    .stTabs [data-baseweb="tab-list"] button {
        background-color: #0d1f2d !important;
        border: 1px solid #2a4a6b !important;
        border-bottom: none !important;
        margin-right: 4px;
        border-radius: 4px 4px 0 0;
        padding: 8px 16px;
    }
    .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] {
        background-color: #1a3348 !important;
        border-bottom: 2px solid #4a8aba !important;
        color: #ffffff !important;
    }
    .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] p {
        color: #ffffff !important;
    }
    /* Progress bar */
    .stProgress > div > div {
        background-color: #4a8aba !important;
    }
    .stProgress > div {
        background-color: #1a3348 !important;
    }
    /* Status (вычисление хэшей) */
    .stStatus {
        background-color: #0d1f2d !important;
        border: 1px solid #2a4a6b !important;
        color: #c8d6e5 !important;
    }
    /* Кнопки загрузки файлов */
    .stFileUploader {
        background-color: #0d1f2d !important;
        border: 1px dashed #2a5a7a !important;
        border-radius: 4px;
        padding: 10px;
    }
    .stFileUploader:hover {
        border-color: #4a8aba !important;
        background-color: #112a3f !important;
    }
</style>
""", unsafe_allow_html=True)

    st.set_page_config(page_title="ssdeep Compare + База", layout="wide")
    st.title("🔍 Dr.D25 Equ4L Ssd33p Ha5hes")

    init_db()

    tab1, tab2, tab3, tab4 = st.tabs([
        "📂 Управление базой",
        "🛡️ Сравнение с базой",
        "🔗 Попарное сравнение",
        "📊 Кластеризация"
    ])

    with tab1:
        st.header("Добавление файлов в базу")
        st.markdown("Загрузите файлы (или ZIP) и укажите тег (название вредоноса).")

        with st.form("add_to_db_form"):
            uploaded_files_db = st.file_uploader(
                "Выберите файлы или ZIP-архивы",
                accept_multiple_files=True,
                type=None,
                key="db_upload"
            )
            tag_input = st.text_input("Тег (например, Trojan.Generic, Ransomware.WannaCry)", "")
            submitted = st.form_submit_button("➕ Добавить в базу")

            if submitted and uploaded_files_db and tag_input:
                hash_map = process_uploaded_files_for_hash(uploaded_files_db)
                if not hash_map:
                    st.warning("Не удалось вычислить хэши.")
                else:
                    count = 0
                    for fname, h in hash_map.items():
                        add_hash_to_db(fname, h, tag_input)
                        count += 1
                    st.success(f"✅ Добавлено {count} записей с тегом '{tag_input}'")
            elif submitted:
                st.warning("Загрузите файлы и укажите тег.")

        st.divider()
        st.header("Просмотр и управление базой")

        if st.button("🔄 Обновить список"):
            st.rerun()

        rows = get_all_hashes()
        if not rows:
            st.info("База пуста.")
        else:
            df_db = pd.DataFrame(rows, columns=["ID", "Имя файла", "Хэш", "Тег", "Дата добавления"])
            st.dataframe(df_db, use_container_width=True)

            st.subheader("Удалить запись")
            with st.form("delete_form"):
                id_to_delete = st.number_input("Введите ID записи для удаления", min_value=1, step=1)
                if st.form_submit_button("🗑️ Удалить"):
                    delete_hash_by_id(id_to_delete)
                    st.success(f"Запись с ID {id_to_delete} удалена.")
                    st.rerun()

   
    with tab2:
        st.header("Проверка файлов по базе вредоносных хэшей")
        st.markdown("Загрузите подозрительные файлы, и мы сравним их с базой.")

        threshold_db = st.slider("Порог схожести с базой (%)", min_value=0, max_value=100, value=70, step=1, key="db_threshold")

        uploaded_files_scan = st.file_uploader(
            "Выберите файлы или ZIP для сканирования",
            accept_multiple_files=True,
            type=None,
            key="scan_upload"
        )

        if st.button("🔍 Сканировать", type="primary"):
            if not uploaded_files_scan:
                st.warning("Загрузите файлы для сканирования.")
            else:
                hash_map = process_uploaded_files_for_hash(uploaded_files_scan)
                if not hash_map:
                    st.error("Не удалось вычислить хэши для загруженных файлов.")
                else:
                    all_results = []
                    for fname, h in hash_map.items():
                        matches = search_in_db(h, threshold_db)
                        for db_fname, db_hash, db_tag, sim in matches:
                            all_results.append({
                                "Проверяемый файл": fname,
                                "Совпавший файл в базе": db_fname,
                                "Тег": db_tag,
                                "Схожесть (%)": sim,
                                "Хэш проверяемого": h,
                                "Хэш из базы": db_hash
                            })

                    if not all_results:
                        st.info("Совпадений с базой не найдено.")
                    else:
                        st.success(f"Найдено совпадений: {len(all_results)}")
                        df_scan = pd.DataFrame(all_results)
                        st.dataframe(df_scan, use_container_width=True)

                        st.subheader("Детали совпадений")
                        for idx, row in enumerate(all_results):
                            with st.expander(f"#{idx+1}: {row['Проверяемый файл']} ↔ {row['Совпавший файл в базе']} (схожесть {row['Схожесть (%)']}%)"):
                                st.text(f"Тег: {row['Тег']}")
                                st.text(f"Хэш проверяемого: {row['Хэш проверяемого']}")
                                st.text(f"Хэш из базы: {row['Хэш из базы']}")
                                parts1 = row['Хэш проверяемого'].split(':')
                                parts2 = row['Хэш из базы'].split(':')
                                if len(parts1) >= 3 and len(parts2) >= 3:
                                    block1, block2 = parts1[1], parts2[1]
                                    c1, c2 = highlight_blocks_advanced(block1, block2)
                                    st.markdown(
                                        f"**Блок проверяемого:** <code style='font-family: monospace;'>{c1}</code>",
                                        unsafe_allow_html=True
                                    )
                                    st.markdown(
                                        f"**Блок из базы:** <code style='font-family: monospace;'>{c2}</code>",
                                        unsafe_allow_html=True
                                    )
                                else:
                                    st.text("(не удалось разобрать блоки)")

    with tab3:
        st.header("Попарное сравнение файлов")
        st.markdown("Сравните несколько файлов между собой.")

        with st.sidebar:
            st.header("Настройки попарного сравнения")
            threshold_pair = st.slider("Порог схожести (%)", min_value=0, max_value=100, value=50, step=1, key="pair_threshold")
            show_hashes_pair = st.checkbox("Показывать полные хэши", value=True, key="pair_hashes")
            show_blocks_pair = st.checkbox("Показывать блоки хэшей", value=True, key="pair_blocks")
            highlight_pair = st.checkbox("Подсвечивать совпадающие участки (красным)", value=False, key="pair_highlight")
            output_csv_pair = st.checkbox("Скачать результаты в CSV", value=False, key="pair_csv")

        uploaded_files_pair = st.file_uploader(
            "Выберите файлы или ZIP для попарного сравнения",
            accept_multiple_files=True,
            type=None,
            key="pair_upload"
        )

        if st.button("🚀 Сравнить попарно", type="primary"):
            if not uploaded_files_pair:
                st.warning("Загрузите файлы.")
            else:
                hash_map = process_uploaded_files_for_hash(uploaded_files_pair)
                if not hash_map or len(hash_map) < 2:
                    st.warning("Нужно минимум 2 файла с корректными хэшами.")
                else:
                    file_list = list(hash_map.keys())
                    results = []
                    total_pairs = len(file_list) * (len(file_list) - 1) // 2
                    progress_bar = st.progress(0, text="Сравнение...")
                    for idx, (i, j) in enumerate(combinations(range(len(file_list)), 2), 1):
                        f1, f2 = file_list[i], file_list[j]
                        h1, h2 = hash_map[f1], hash_map[f2]
                        score = ppdeep.compare(h1, h2)
                        if score >= threshold_pair:
                            results.append((f1, f2, score, h1, h2))
                        progress_bar.progress(idx / total_pairs)
                    progress_bar.empty()

                    if not results:
                        st.info(f"Нет пар с схожестью >= {threshold_pair}%.")
                    else:
                        results.sort(key=lambda x: x[2], reverse=True)
                        st.subheader(f"Найдено пар: {len(results)}")
                        for f1, f2, score, h1, h2 in results:
                            st.markdown(f"`{f1}`  ↔  `{f2}`  —  **{score:3d}%**")
                            if show_hashes_pair:
                                st.text(f"  Хэш1: {h1}")
                                st.text(f"  Хэш2: {h2}")
                            if show_blocks_pair:
                                parts1 = h1.split(':')
                                parts2 = h2.split(':')
                                if len(parts1) >= 3 and len(parts2) >= 3:
                                    block1, block2 = parts1[1], parts2[1]
                                    if highlight_pair:
                                        c1, c2 = highlight_blocks_advanced(block1, block2)
                                        st.markdown(
                                            f"  Блок1: <code style='font-family: monospace;'>{c1}</code>",
                                            unsafe_allow_html=True
                                        )
                                        st.markdown(
                                            f"  Блок2: <code style='font-family: monospace;'>{c2}</code>",
                                            unsafe_allow_html=True
                                        )
                                    else:
                                        st.text(f"  Блок1: {block1}")
                                        st.text(f"  Блок2: {block2}")
                                else:
                                    st.text("  (не удалось разобрать блоки)")
                            st.divider()

                        if output_csv_pair:
                            csv_rows = []
                            for f1, f2, score, h1, h2 in results:
                                row = {"Файл 1": f1, "Файл 2": f2, "Схожесть (%)": score}
                                if show_hashes_pair:
                                    row["Хэш 1"] = h1
                                    row["Хэш 2"] = h2
                                if show_blocks_pair:
                                    parts1 = h1.split(':')
                                    parts2 = h2.split(':')
                                    if len(parts1) >= 3 and len(parts2) >= 3:
                                        row["Основной блок 1"] = parts1[1]
                                        row["Основной блок 2"] = parts2[1]
                                    else:
                                        row["Основной блок 1"] = "(недоступно)"
                                        row["Основной блок 2"] = "(недоступно)"
                                csv_rows.append(row)
                            output = io.StringIO()
                            writer = csv.DictWriter(output, fieldnames=csv_rows[0].keys())
                            writer.writeheader()
                            for row in csv_rows:
                                clean_row = {}
                                for k, v in row.items():
                                    if isinstance(v, str) and '<span' in v:
                                        clean_row[k] = re.sub(r'<[^>]+>', '', v)
                                    else:
                                        clean_row[k] = v
                                writer.writerow(clean_row)
                            st.download_button("📥 Скачать CSV", data=output.getvalue(), file_name="pair_results.csv", mime="text/csv")

    with tab4:
        st.header("Кластеризация файлов")
        st.markdown("Группировка файлов по схожести.")

        with st.sidebar:
            st.header("Настройки кластеризации")
            threshold_cluster = st.slider("Порог схожести (%)", min_value=0, max_value=100, value=50, step=1, key="cluster_threshold")
            min_cluster_size = st.number_input("Минимальный размер кластера", min_value=2, value=2, step=1, key="cluster_min")
            show_hashes_cluster = st.checkbox("Показывать полные хэши", value=False, key="cluster_hashes")
            show_blocks_cluster = st.checkbox("Показывать блоки хэшей", value=False, key="cluster_blocks")
            highlight_cluster = st.checkbox("Подсвечивать совпадающие участки (красным)", value=False, key="cluster_highlight")

        uploaded_files_cluster = st.file_uploader(
            "Выберите файлы или ZIP для кластеризации",
            accept_multiple_files=True,
            type=None,
            key="cluster_upload"
        )

        if st.button("📊 Кластеризовать", type="primary"):
            if not uploaded_files_cluster:
                st.warning("Загрузите файлы.")
            else:
                hash_map = process_uploaded_files_for_hash(uploaded_files_cluster)
                if not hash_map or len(hash_map) < 2:
                    st.warning("Нужно минимум 2 файла с корректными хэшами.")
                else:
                    file_list = list(hash_map.keys())
                    clusters = find_clusters(file_list, hash_map, threshold_cluster)
                    clusters = [c for c in clusters if len(c) >= min_cluster_size]

                    if not clusters:
                        st.info(f"Нет кластеров размером >= {min_cluster_size} и схожестью >= {threshold_cluster}%.")
                    else:
                        st.subheader(f"Найдено кластеров: {len(clusters)}")
                        for idx, cluster in enumerate(clusters, 1):
                            with st.expander(f"📁 Кластер #{idx} (размер {len(cluster)})", expanded=True):
                                if show_blocks_cluster and highlight_cluster:
                                    st.markdown("**Попарное сравнение внутри кластера (с подсветкой):**")
                                    for i in range(len(cluster)):
                                        for j in range(i+1, len(cluster)):
                                            f1, f2 = cluster[i], cluster[j]
                                            h1, h2 = hash_map[f1], hash_map[f2]
                                            score = ppdeep.compare(h1, h2)
                                            if score >= threshold_cluster:
                                                st.markdown(f"`{f1}` ↔ `{f2}`  —  **схожесть {score}%**")
                                                parts1 = h1.split(':')
                                                parts2 = h2.split(':')
                                                if len(parts1) >= 3 and len(parts2) >= 3:
                                                    block1, block2 = parts1[1], parts2[1]
                                                    c1, c2 = highlight_blocks_simple(block1, block2)
                                                    st.markdown(
                                                        f"  Блок1: <code style='font-family: monospace;'>{c1}</code>",
                                                        unsafe_allow_html=True
                                                    )
                                                    st.markdown(
                                                        f"  Блок2: <code style='font-family: monospace;'>{c2}</code>",
                                                        unsafe_allow_html=True
                                                    )
                                                else:
                                                    st.text("  (не удалось разобрать блоки)")
                                elif show_hashes_cluster:
                                    for f in cluster:
                                        st.text(f"{f}: {hash_map[f]}")
                                else:
                                    for f in cluster:
                                        st.text(f)

if __name__ == "__main__":
    main()
