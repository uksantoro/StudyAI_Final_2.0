# StudyAI Final 2.0

Versione completa e operativa senza API AI esterne. L'AI verrà integrata in una fase successiva.

## Funzioni operative
- Registrazione e login JWT
- Dashboard responsive desktop/mobile
- Corsi, materie e lezioni: creazione, modifica, eliminazione
- Ricerca globale
- Caricamento/riproduzione/eliminazione audio (MP3, WAV, M4A, OGG, WEBM)
- Note per le lezioni
- Trascrizione modificabile
- Riassunto modificabile
- Concetti principali
- Mappa concettuale visuale
- Flashcard: creazione, modifica, eliminazione e modalità studio
- Quiz: creazione domande, svolgimento e punteggio
- Tutor locale demo basato sui contenuti della lezione (nessuna API)
- Statistiche e progresso
- Layout responsive pensato separatamente per PC e mobile
- Database SQLite persistente

## Avvio
```powershell
cd C:\percorso\studyai_final\backend
npm install
Copy-Item .env.example .env
npm start
```
Apri `http://localhost:3000`.

## Dati
Il database viene creato automaticamente come `studyai.sqlite`.
Per mantenere un database precedente, fare un backup e copiarlo nella cartella backend solo se lo schema è compatibile.

## AI futura
I punti di integrazione sono già isolati nelle azioni di lezione e tutor. Non sono presenti chiavi API nel progetto.
