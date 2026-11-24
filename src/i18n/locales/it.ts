export const it = {
  attachmentCollector: {
    confirm: 'Vuoi raccogliere in modo ricorsivo gli allegati di tutte le note nelle cartelle?\n{{folders}}\nQuesta operazione non può essere annullata.',
    progressBar: {
      message: 'Raccolta allegati {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Raccolta allegati...'
    }
  },
  buttons: {
    copy: 'Copia',
    move: 'Sposta',
    previewAttachmentFile: 'Anteprima file allegato',
    skip: 'Salta'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'L\'allegato {{attachment}} è referenziato da più note.',
    heading: 'Raccolta allegato usato da più note',
    noPriorityWinnerReason: {
      EmptyList: 'Non è stato spostato perché l\'impostazione {{settingName}} è vuota, quindi nulla decide a quale di queste note appartenga.',
      NoMatch: 'Non è stato spostato perché nessuna di queste note corrisponde ad alcuna voce dell\'impostazione {{settingName}}.',
      Tie: 'Non è stato spostato perché diverse di queste note corrispondono all\'impostazione {{settingName}} allo stesso modo, quindi non indica un unico proprietario.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Dovresti usare la stessa azione per altri allegati problematici'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Raccogli allegati nella cartella corrente',
    collectAttachmentsCurrentNote: 'Raccogli allegati nella nota corrente',
    collectAttachmentsEntireVault: 'Raccogli allegati nell\'intero vault'
  },
  links: {
    documentation: 'documentazione',
    tokens: 'token'
  },
  menuItems: {
    collectAttachmentsInFile: 'Raccogli allegati nel file',
    collectAttachmentsInFiles: 'Raccogli allegati nei file'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Raccolta allegati per \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Raccolta allegati annullata. Consulta la console per i dettagli.',
    generatedAttachmentFileNameIsInvalid: 'Il nome file allegato generato \'{{path}}\' non è valido.\n{{validationMessage}}\nControlla l\'impostazione {{settingName}}.',
    notePathIsIgnored: 'Il percorso della nota è ignorato'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Annulla',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Elementi per pagina:',
      jumpToPage: 'Vai alla pagina:'
    },
    notices: {
      attachmentIsStillUsed: 'L\'allegato {{attachmentPath}} è ancora in uso da altre note. Non sarà eliminato.',
      unhandledError: 'Si è verificato un errore non gestito. Controlla la console per ulteriori informazioni.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'tutti i file vengono rinominati.',
        displayText: 'Tutti'
      },
      none: {
        description: 'i loro nomi vengono preservati.',
        displayText: 'Nessuno'
      },
      onlyPastedImages: {
        description: 'solo le immagini incollate vengono rinominate. Si applica solo quando il contenuto dell\'immagine PNG viene incollato direttamente dagli appunti. Tipicamente, per incollare screenshot.',
        displayText: 'Solo immagini incollate'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'annulla la raccolta allegati.',
        displayText: 'Annulla'
      },
      copy: {
        description: 'copia l\'allegato nella nuova posizione.',
        displayText: 'Copia'
      },
      move: {
        description: 'sposta l\'allegato nella nuova posizione.',
        displayText: 'Sposta'
      },
      prompt: {
        description: 'chiedi all\'utente di scegliere l\'azione.',
        displayText: 'Richiedi'
      },
      skip: {
        description: 'salta l\'allegato e procedi al successivo.',
        displayText: 'Salta'
      }
    },
    defaultImageSizeDimension: {
      height: 'Altezza',
      width: 'Larghezza'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// I token personalizzati sono stati commentati poiché devono essere aggiornati al nuovo formato introdotto nella versione 9.0.0 del plugin.\n// Consulta la documentazione ({{customTokensDocumentationUrl}}) per maggiori informazioni.',
      deprecated: 'Il formato di registrazione dei token personalizzati è cambiato. Aggiorna i tuoi token di conseguenza. Consulta la {{documentation}} per maggiori informazioni.'
    },
    legacyRenameAttachmentsToLowerCase: 'L\'impostazione {{setting}} è deprecata. Usa invece il formato {{format}}. Consulta la {{documentation}} per maggiori informazioni.',
    markdownUrlFormat: {
      deprecated: 'Potresti aver impostato un valore errato per il formato {{setting}}. Consulta la {{documentation}} per maggiori informazioni. Questo messaggio non verrà più mostrato.'
    },
    specialCharacters: 'Il valore predefinito dell\'impostazione {{setting}} è stato modificato. Il tuo valore è stato aggiornato al nuovo valore predefinito.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'La dimensione predefinita dell\'immagine deve essere in pixel o percentuale',
      invalidCustomTokensCode: 'Codice token personalizzati non valido',
      invalidRegularExpression: 'Espressione regolare non valida {{regExp}}',
      specialCharactersMustNotContainSlash: 'I caratteri speciali non devono contenere /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'La sostituzione dei caratteri speciali non deve contenere caratteri di percorso nome file non validi.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Quando si allegano file:',
      name: 'Modalità rinomina allegati'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Quando l\'allegato raccolto è usato da più note:',
      name: 'Modalità raccolta allegato usato da più note'
    },
    collectedAttachmentFileName: {
      description: 'Vedi i {{tokens}} disponibili.\nLascia vuoto per mantenere il nome file attuale dell\'allegato.',
      name: 'Nome file allegato raccolto'
    },
    customTokens: {
      description: 'Token personalizzati da utilizzare.\nConsulta la {{documentation}} per maggiori informazioni.\n⚠️ I token personalizzati possono essere codice JavaScript arbitrario. Se scritti male, possono causare perdita di dati. Usali a tuo rischio.',
      name: 'Token personalizzati'
    },
    defaultImageSize: {
      description: 'Dimensione predefinita dell\'immagine.\nPuò essere specificata in pixel ({{pixels}}) o come percentuale della dimensione totale dell\'immagine ({{percentage}}).\nLascia vuoto per usare la dimensione originale dell\'immagine.',
      name: 'Dimensione immagine predefinita'
    },
    duplicateNameSeparator: {
      description: 'Quando incolli o trascini un file con lo stesso nome di un file esistente, questo separatore verrà aggiunto al nome del file.\nAd es., quando trascini il file {{existingFile}}, verrà rinominato in {{firstAvailableName}}, {{secondAvailableName}}, ecc., scegliendo il primo nome disponibile.',
      name: 'Separatore nome duplicato'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Escludi gli allegati dai seguenti percorsi quando viene eseguito il comando {{command}}.\nInserisci ogni percorso su una nuova riga.\n{{pathSyntax}}\nSe l\'impostazione è vuota, nessun percorso viene escluso dalla raccolta allegati.',
      name: 'Percorsi esclusi dalla raccolta allegati'
    },
    generatedAttachmentFileName: {
      description: 'Vedi i {{tokens}} disponibili.',
      name: 'Nome file allegato generato'
    },
    jpegQuality: {
      description: 'Più piccola è la qualità, maggiore è il rapporto di compressione.',
      name: 'Qualità JPEG'
    },
    locationForNewAttachments: {
      description: 'Inizia con {{relativePrefix}} per i percorsi relativi alla cartella padre della nota.\nVedi i {{tokens}} disponibili.\nLe cartelle che iniziano con un punto, come {{dotFolder}}, non sono consigliate, perché Obsidian non le traccia. Potresti dover usare il plugin {{unhidePlugin}} per gestirle.',
      name: 'Posizione per nuovi allegati'
    },
    markdownUrlFormat: {
      description: 'Formato dell\'URL che verrà inserito in Markdown quando viene aggiunto un allegato. Si applica solo in quel momento: un link che Obsidian riscrive in seguito, quando una nota o un allegato viene rinominato o spostato, riceve il formato predefinito.\nVedi i {{tokens}} disponibili.\nLascia vuoto per usare il formato predefinito.',
      name: 'Formato URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Se applicare le impostazioni di cartella allegati e nome file agli allegati creati da ALTRI plugin.\nAlcuni plugin scrivono un allegato nel vault con un nome proprio, senza chiedere a Obsidian dove debba andare. Con questa opzione attiva, un file simile viene spostato e rinominato non appena compare.\nVengono toccati solo i file creati mentre una nota è aperta e collegati da una nota: un file a cui nessuna nota rimanda è un dato che un altro plugin tiene per sé, e resta dove è stato scritto. I file che arrivano da una sincronizzazione o da un\'importazione del vault non vengono mai toccati.\n{{modes}}\nIl plugin che crea il file viene identificato dallo stack delle chiamate della scrittura. È un tentativo non garantito: nessun plugin viene identificato per un file scritto da Obsidian stesso, da un client di sincronizzazione o da un plugin che rimanda la scrittura. Un file simile conta come NON presente nell\'elenco sottostante.',
      name: 'Rinomina gli allegati creati da altri plugin'
    },
    renameAttachmentsToLowerCase: 'Rinomina allegati in minuscolo',
    renamedAttachmentFileName: {
      description: 'Vedi i {{tokens}} disponibili.\nLascia vuoto per mantenere il nome file attuale dell\'allegato.',
      name: 'Nome file allegato rinominato'
    },
    resetToSampleCustomTokens: {
      message: 'Sei sicuro di voler ripristinare i token personalizzati ai token personalizzati di esempio? Le tue modifiche andranno perse.',
      title: 'Ripristina ai token personalizzati di esempio'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Se convertire le immagini incollate in JPEG. Si applica solo quando il contenuto dell\'immagine PNG viene incollato direttamente dagli appunti. Tipicamente, per incollare screenshot.',
      name: 'Converti immagini incollate in JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Se abilitato, gli allegati elaborati tramite i comandi {{command}} verranno rinominati secondo l\'impostazione {{setting}}.',
      name: 'Rinomina allegati raccolti'
    },
    specialCharacters: {
      description: 'Caratteri speciali nel nome della cartella e del file allegato da sostituire o rimuovere.\nLascia vuoto per preservare i caratteri speciali.',
      name: 'Caratteri speciali'
    },
    specialCharactersReplacement: {
      description: 'Stringa di sostituzione per i caratteri speciali nel nome della cartella e del file allegato.\nLascia vuoto per rimuovere i caratteri speciali.',
      name: 'Sostituzione caratteri speciali'
    },
    timeoutInSeconds: {
      description: 'Il timeout in secondi per tutte le operazioni.\nSe è impostato {{zero}}, il timeout di esecuzione delle operazioni è disabilitato.',
      name: 'Timeout in secondi'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Rinomina file allegato',
    folderTitle: 'Scegli cartella allegati',
    previewModal: {
      title: 'Anteprima file allegato \'{{fullFileName}}\''
    },
    title: 'Fornisci un valore per il token prompt'
  },
  regularExpression: '/espressione regolare/'
};
