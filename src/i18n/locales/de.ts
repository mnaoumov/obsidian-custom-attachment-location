export const de = {
  attachmentCollector: {
    confirm: {
      part1: 'Möchten Sie Anhänge für alle Notizen in Ordnern rekursiv sammeln?',
      part2: 'Dieser Vorgang kann nicht rückgängig gemacht werden.'
    },
    progressBar: {
      message: 'Sammle Anhänge {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Sammle Anhänge...'
    }
  },
  buttons: {
    copy: 'Kopieren',
    move: 'Verschieben',
    previewAttachmentFile: 'Anhang-Datei anzeigen',
    skip: 'Überspringen'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: {
      part1: 'Anhang',
      part2: 'wird von mehreren Notizen referenziert.'
    },
    heading: 'Sammle Anhang, der von mehreren Notizen verwendet wird',
    noPriorityWinnerReason: {
      EmptyList: 'Er wurde nicht verschoben, weil die Einstellung {{settingName}} leer ist, sodass nichts entscheidet, welcher dieser Notizen er gehört.',
      NoMatch: 'Er wurde nicht verschoben, weil keine dieser Notizen zu einem Eintrag in der Einstellung {{settingName}} passt.',
      Tie: 'Er wurde nicht verschoben, weil mehrere dieser Notizen gleich gut zur Einstellung {{settingName}} passen, sodass sie keinen einzelnen Eigentümer benennt.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Sollte dieselbe Aktion für andere problematische Anhänge verwenden'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Sammle Anhänge im aktuellen Ordner',
    collectAttachmentsCurrentNote: 'Sammle Anhänge in der aktuellen Notiz',
    collectAttachmentsEntireVault: 'Sammle Anhänge im gesamten Vault'
  },
  menuItems: {
    collectAttachmentsInFile: 'Anhänge in Datei sammeln',
    collectAttachmentsInFiles: 'Anhänge in Dateien sammeln'
  },
  notice: {
    collectingAttachments: 'Sammle Anhänge für \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Sammeln von Anhängen abgebrochen. Siehe Konsole für Details.',
    generatedAttachmentFileNameIsInvalid: {
      part1: 'Generierter Anhang-Dateiname \'{{path}}\' ist ungültig.\n{{validationMessage}}\nÜberprüfen Sie Ihre',
      part2: 'Einstellung.'
    },
    notePathIsIgnored: 'Notiz-Pfad wird ignoriert'
  },
  obsidianDevUtils: {
    buttons: {
      cancel: 'Abbrechen',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Elemente pro Seite:',
      jumpToPage: 'Springe zu Seite:'
    },
    notices: {
      attachmentIsStillUsed: 'Anhang {{attachmentPath}} wird noch von anderen Notizen verwendet. Er wird nicht gelöscht.',
      unhandledError: 'Ein unbehandelter Fehler ist aufgetreten. Bitte überprüfen Sie die Konsole für weitere Informationen.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'alle Dateien werden umbenannt.',
        displayText: 'Alle'
      },
      none: {
        description: 'ihre Namen werden beibehalten.',
        displayText: 'Keine'
      },
      onlyPastedImages: {
        description: 'nur eingefügte Bilder werden umbenannt. Gilt nur, wenn der PNG-Bildinhalt direkt aus der Zwischenablage eingefügt wird. Typischerweise für das Einfügen von Screenshots.',
        displayText: 'Nur eingefügte Bilder'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'das Sammeln von Anhängen abbrechen.',
        displayText: 'Abbrechen'
      },
      copy: {
        description: 'den Anhang an den neuen Speicherort kopieren.',
        displayText: 'Kopieren'
      },
      move: {
        description: 'den Anhang an den neuen Speicherort verschieben.',
        displayText: 'Verschieben'
      },
      prompt: {
        description: 'den Benutzer zur Auswahl der Aktion auffordern.',
        displayText: 'Auffordern'
      },
      skip: {
        description: 'den Anhang überspringen und zum nächsten fortfahren.',
        displayText: 'Überspringen'
      }
    },
    defaultImageSizeDimension: {
      height: 'Höhe',
      width: 'Breite'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Benutzerdefinierte Tokens wurden auskommentiert, da sie auf das neue Format aktualisiert werden müssen, das in Plugin-Version 9.0.0 eingeführt wurde.\n// Siehe Dokumentation (https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#custom-tokens) für weitere Informationen.',
      deprecated: {
        part1: 'In Plugin-Version 9.0.0 hat sich das Format der benutzerdefinierten Token-Registrierung geändert. Bitte aktualisieren Sie Ihre Tokens entsprechend. Siehe',
        part2: 'Dokumentation',
        part3: 'für weitere Informationen'
      }
    },
    legacyRenameAttachmentsToLowerCase: {
      part1: 'In Plugin-Version 9.0.0 ist die',
      part2: 'Einstellung veraltet. Verwenden Sie stattdessen das',
      part3: 'Format. Siehe',
      part4: 'Dokumentation',
      part5: 'für weitere Informationen'
    },
    markdownUrlFormat: {
      deprecated: {
        part1: 'Sie haben möglicherweise einen falschen Wert für das',
        part2: 'Format gesetzt. Bitte siehe',
        part3: 'Dokumentation',
        part4: 'für weitere Informationen',
        part5: 'Diese Nachricht wird nicht erneut angezeigt.'
      }
    },
    specialCharacters: {
      part1: 'In Plugin-Version 9.16.0 wurde der',
      part2: 'Standard-Einstellungswert geändert. Ihr Einstellungswert wurde auf den neuen Standardwert aktualisiert.'
    },
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Die Standardbildgröße muss in Pixel oder Prozent angegeben werden',
      invalidCustomTokensCode: 'Ungültiger benutzerdefinierter Token-Code',
      invalidRegularExpression: 'Ungültiger regulärer Ausdruck {{regExp}}',
      specialCharactersMustNotContainSlash: 'Sonderzeichen dürfen nicht / enthalten',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Sonderzeichen-Ersetzung darf keine ungültigen Dateiname-Pfad-Zeichen enthalten.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: {
        part1: 'Beim Anhängen von Dateien:'
      },
      name: 'Anhang-Umbenennungsmodus'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: {
        part1: 'Wenn der gesammelte Anhang von mehreren Notizen verwendet wird:'
      },
      name: 'Sammle Anhang, der von mehreren Notizen verwendet wird - Modus'
    },
    collectedAttachmentFileName: {
      description: {
        part1: 'Siehe verfügbare',
        part2: 'Tokens',
        part3: 'Leer lassen, um den ursprünglichen Anhang-Dateinamen beizubehalten.'
      },
      name: 'Gesammelter Anhang-Dateiname'
    },
    customTokens: {
      description: {
        part1: 'Zu verwendende benutzerdefinierte Tokens.',
        part2: 'Siehe',
        part3: 'Dokumentation',
        part4: 'für weitere Informationen.',
        part5: '⚠️ Benutzerdefinierte Tokens können beliebiger JavaScript-Code sein. Wenn sie schlecht geschrieben sind, können sie Datenverlust verursachen. Verwenden Sie sie auf eigene Gefahr.'
      },
      name: 'Benutzerdefinierte Tokens'
    },
    defaultImageSize: {
      description: {
        part1: 'Die Standardbildgröße.',
        part2: 'Kann in Pixel angegeben werden',
        part3: 'oder als Prozentsatz der vollen Bildgröße',
        part4: 'Frei lassen, um die Originalgröße zu verwenden.'
      },
      name: 'Standardbildgröße'
    },
    duplicateNameSeparator: {
      description: {
        part1: 'Wenn Sie eine Datei mit demselben Namen wie eine bestehende Datei einfügen/ziehen, wird dieser Separator zum Dateinamen hinzugefügt.',
        part2: 'Z.B., wenn Sie die Datei',
        part3: 'ziehen, wird sie umbenannt zu',
        part4: ', usw., um den ersten verfügbaren Namen zu erhalten.'
      },
      name: 'Duplikat-Namen-Separator'
    },
    excludePathsFromAttachmentCollecting: {
      description: {
        part1: 'Anhänge von den folgenden Pfaden ausschließen, wenn',
        part2: 'Anhänge sammeln',
        part3: 'Befehl ausgeführt wird.',
        part4: 'Jeden Pfad in eine neue Zeile einfügen.',
        part5: 'Sie können Pfad-String oder',
        part6: 'Wenn die Einstellung leer ist, werden keine Pfade vom Sammeln von Anhängen ausgeschlossen.'
      },
      name: 'Pfade vom Sammeln von Anhängen ausschließen'
    },
    generatedAttachmentFileName: {
      description: {
        part1: 'Siehe verfügbare',
        part2: 'Tokens'
      },
      name: 'Generierter Anhang-Dateiname'
    },
    jpegQuality: {
      description: 'Je kleiner die Qualität, desto größer das Kompressionsverhältnis.',
      name: 'JPEG-Qualität'
    },
    locationForNewAttachments: {
      description: {
        part1: 'Beginnen Sie mit',
        part2: 'um relativen Pfad zu verwenden.',
        part3: 'Siehe verfügbare',
        part4: 'Tokens',
        part5: 'Punkt-Ordner wie',
        part6: 'werden nicht empfohlen, da Obsidian sie nicht verfolgt. Sie müssen möglicherweise ein',
        part7: 'Plugin verwenden, um sie zu verwalten.'
      },
      name: 'Speicherort für neue Anhänge'
    },
    markdownUrlFormat: {
      description: {
        part1: 'Format für die URL, die in Markdown eingefügt wird.',
        part2: 'Siehe verfügbare',
        part3: 'Tokens',
        part4: 'Leer lassen, um das Standardformat zu verwenden.'
      },
      name: 'Markdown URL-Format'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: {
        part1: 'Ob die Einstellungen für Anhang-Ordner und Dateiname auch auf Anhänge angewendet werden, die ANDERE Plugins erstellen.',
        part2: 'Manche Plugins schreiben einen Anhang unter einem eigenen Namen direkt in den Tresor, ohne Obsidian zu fragen, wohin er gehört. Ist dies aktiviert, wird eine solche Datei unmittelbar nach ihrem Auftauchen verschoben und umbenannt.',
        part3: 'Betroffen sind nur Dateien, die bei geöffneter Notiz entstehen — niemals Dateien aus einer Synchronisierung oder einem Tresor-Import.'
      },
      name: 'Von anderen Plugins erstellte Anhänge umbenennen'
    },
    renameAttachmentsToLowerCase: 'Anhänge in Kleinbuchstaben umbenennen',
    renamedAttachmentFileName: {
      description: {
        part1: 'Siehe verfügbare',
        part2: 'Tokens',
        part3: 'Leer lassen, um den ursprünglichen Anhang-Dateinamen beizubehalten.'
      },
      name: 'Umbenannter Anhang-Dateiname'
    },
    resetToSampleCustomTokens: {
      message: 'Sind Sie sicher, dass Sie die benutzerdefinierten Tokens auf die Beispiel-Tokens zurücksetzen möchten? Ihre Änderungen gehen verloren.',
      title: 'Auf Beispiel-Tokens zurücksetzen'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Ob eingefügte Bilder in JPEG konvertiert werden sollen. Gilt nur, wenn der PNG-Bildinhalt direkt aus der Zwischenablage eingefügt wird. Typischerweise für das Einfügen von Screenshots.',
      name: 'Soll eingefügte Bilder in JPEG konvertieren'
    },
    shouldRenameCollectedAttachments: {
      description: {
        part1: 'Wenn aktiviert, werden Anhänge, die über',
        part2: 'Anhänge sammeln',
        part3: 'Befehle verarbeitet werden, entsprechend der',
        part4: 'Einstellung umbenannt.'
      },
      name: 'Soll gesammelte Anhänge umbenennen'
    },
    specialCharacters: {
      description: {
        part1: 'Sonderzeichen in Anhang-Ordner und Dateiname, die ersetzt oder entfernt werden sollen.',
        part2: 'Leer lassen, um Sonderzeichen zu erhalten.'
      },
      name: 'Sonderzeichen'
    },
    specialCharactersReplacement: {
      description: {
        part1: 'Ersetzungsstring für Sonderzeichen in Anhang-Ordner und Dateiname.',
        part2: 'Leer lassen, um Sonderzeichen zu entfernen.'
      },
      name: 'Sonderzeichen-Ersetzung'
    },
    timeoutInSeconds: {
      description: {
        part1: 'Das Timeout in Sekunden für alle Operationen.',
        part2: 'Wenn',
        part3: 'gesetzt ist, ist das Ausführungs-Timeout für Operationen deaktiviert.'
      },
      name: 'Timeout in Sekunden'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Anhang-Datei umbenennen',
    folderTitle: 'Anhang-Ordner wählen',
    previewModal: {
      title: 'Anhang-Datei anzeigen \'{{fullFileName}}\''
    },
    title: 'Geben Sie einen Wert für den Prompt-Token an'
  },
  regularExpression: '/regulärer Ausdruck/'
};
