export const de = {
  attachmentCollector: {
    confirm: 'Möchten Sie Anhänge für alle Notizen in den folgenden Ordnern rekursiv sammeln?\n{{folders}}\nDieser Vorgang kann nicht rückgängig gemacht werden.',
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
    content: 'Der Anhang {{attachment}} wird von mehreren Notizen referenziert.',
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
  links: {
    documentation: 'Dokumentation',
    tokens: 'Tokens'
  },
  menuItems: {
    collectAttachmentsInFile: 'Anhänge in Datei sammeln',
    collectAttachmentsInFiles: 'Anhänge in Dateien sammeln'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Sammle Anhänge für \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Sammeln von Anhängen abgebrochen. Siehe Konsole für Details.',
    generatedAttachmentFileNameIsInvalid: 'Der generierte Anhang-Dateiname \'{{path}}\' ist ungültig.\n{{validationMessage}}\nÜberprüfen Sie Ihre Einstellung {{settingName}}.',
    notePathIsIgnored: 'Notiz-Pfad wird ignoriert'
  },
  obsidianLib: {
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
      codeComment: '// Benutzerdefinierte Tokens wurden auskommentiert, da sie auf das neue Format aktualisiert werden müssen, das in Plugin-Version 9.0.0 eingeführt wurde.\n// Siehe Dokumentation ({{customTokensDocumentationUrl}}) für weitere Informationen.',
      deprecated: 'Das Format der Registrierung benutzerdefinierter Tokens hat sich geändert. Bitte aktualisieren Sie Ihre Tokens entsprechend. Weitere Informationen finden Sie in der {{documentation}}.'
    },
    legacyRenameAttachmentsToLowerCase: 'Die Einstellung {{setting}} ist veraltet. Verwenden Sie stattdessen das Format {{format}}. Weitere Informationen finden Sie in der {{documentation}}.',
    markdownUrlFormat: {
      deprecated: 'Für das Format {{setting}} ist möglicherweise ein falscher Wert eingestellt. Weitere Informationen finden Sie in der {{documentation}}. Diese Nachricht wird nicht erneut angezeigt.'
    },
    specialCharacters: 'Der Standardwert der Einstellung {{setting}} wurde geändert. Ihr Einstellungswert wurde auf den neuen Standardwert aktualisiert.',
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
      description: 'Beim Anhängen von Dateien:',
      name: 'Anhang-Umbenennungsmodus'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Wenn der gesammelte Anhang von mehreren Notizen verwendet wird:',
      name: 'Sammle Anhang, der von mehreren Notizen verwendet wird - Modus'
    },
    collectedAttachmentFileName: {
      description: 'Siehe die verfügbaren {{tokens}}.\nLeer lassen, um den aktuellen Anhang-Dateinamen beizubehalten.',
      name: 'Gesammelter Anhang-Dateiname'
    },
    customTokens: {
      description: 'Zu verwendende benutzerdefinierte Tokens.\nWeitere Informationen finden Sie in der {{documentation}}.\n⚠️ Benutzerdefinierte Tokens können beliebiger JavaScript-Code sein. Wenn sie schlecht geschrieben sind, können sie Datenverlust verursachen. Verwenden Sie sie auf eigene Gefahr.',
      name: 'Benutzerdefinierte Tokens'
    },
    defaultImageSize: {
      description: 'Die Standardbildgröße.\nKann in Pixeln ({{pixels}}) oder als Prozentsatz der vollen Bildgröße ({{percentage}}) angegeben werden.\nFrei lassen, um die Originalgröße zu verwenden.',
      name: 'Standardbildgröße'
    },
    duplicateNameSeparator: {
      description: 'Wenn Sie eine Datei mit demselben Namen wie eine bestehende Datei einfügen/ziehen, wird dieser Separator zum Dateinamen hinzugefügt.\nWenn Sie z. B. die Datei {{existingFile}} ziehen, wird sie in {{firstAvailableName}}, {{secondAvailableName}} usw. umbenannt, je nachdem, welcher Name als erster verfügbar ist.',
      name: 'Duplikat-Namen-Separator'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Anhänge aus den folgenden Pfaden ausschließen, wenn der Befehl {{command}} ausgeführt wird.\nJeden Pfad in eine neue Zeile einfügen.\n{{pathSyntax}}\nWenn die Einstellung leer ist, werden keine Pfade vom Sammeln von Anhängen ausgeschlossen.',
      name: 'Pfade vom Sammeln von Anhängen ausschließen'
    },
    generatedAttachmentFileName: {
      description: 'Siehe die verfügbaren {{tokens}}.',
      name: 'Generierter Anhang-Dateiname'
    },
    jpegQuality: {
      description: 'Je kleiner die Qualität, desto größer das Kompressionsverhältnis.',
      name: 'JPEG-Qualität'
    },
    locationForNewAttachments: {
      description: 'Beginnen Sie mit {{relativePrefix}} für Pfade relativ zum übergeordneten Ordner der Notiz.\nSiehe die verfügbaren {{tokens}}.\nPunkt-Ordner wie {{dotFolder}} werden nicht empfohlen, da Obsidian sie nicht verfolgt. Möglicherweise benötigen Sie das Plugin {{unhidePlugin}}, um sie zu verwalten.',
      name: 'Speicherort für neue Anhänge'
    },
    markdownUrlFormat: {
      description: 'Format für die URL, die beim Hinzufügen eines Anhangs in Markdown eingefügt wird. Es gilt nur in diesem Moment: Ein Link, den Obsidian später neu schreibt, wenn eine Notiz oder ein Anhang umbenannt oder verschoben wird, erhält das Standardformat.\nSiehe die verfügbaren {{tokens}}.\nLeer lassen, um das Standardformat zu verwenden.',
      name: 'Markdown URL-Format'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description:
        'Ob die Einstellungen für Anhang-Ordner und Dateiname auch auf Anhänge angewendet werden, die ANDERE Plugins erstellen.\nManche Plugins schreiben einen Anhang unter einem eigenen Namen direkt in den Tresor, ohne Obsidian zu fragen, wohin er gehört. Ist dies aktiviert, wird eine solche Datei unmittelbar nach ihrem Auftauchen verschoben und umbenannt.\nBetroffen sind nur Dateien, die bei geöffneter Notiz entstehen und von einer Notiz verlinkt werden: Eine Datei, auf die keine Notiz verlinkt, enthält Daten, die ein anderes Plugin für sich selbst aufbewahrt, und bleibt dort, wo sie geschrieben wurde. Dateien aus einer Synchronisierung oder einem Tresor-Import werden nie angefasst.\n{{modes}}\nDas erstellende Plugin wird anhand des Aufrufstapels des Schreibvorgangs ermittelt. Das geschieht nach bestem Bemühen: Für eine Datei, die Obsidian selbst, ein Sync-Client oder ein Plugin schreibt, das seinen Schreibvorgang aufschiebt, wird kein Plugin ermittelt. Eine solche Datei gilt als NICHT in der Liste unten enthalten.',
      name: 'Von anderen Plugins erstellte Anhänge umbenennen'
    },
    renameAttachmentsToLowerCase: 'Anhänge in Kleinbuchstaben umbenennen',
    renamedAttachmentFileName: {
      description: 'Siehe die verfügbaren {{tokens}}.\nLeer lassen, um den aktuellen Anhang-Dateinamen beizubehalten.',
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
      description: 'Wenn aktiviert, werden Anhänge, die über die Befehle {{command}} verarbeitet werden, gemäß der Einstellung {{setting}} umbenannt.',
      name: 'Soll gesammelte Anhänge umbenennen'
    },
    specialCharacters: {
      description: 'Sonderzeichen in Anhang-Ordner und Dateiname, die ersetzt oder entfernt werden sollen.\nLeer lassen, um Sonderzeichen zu erhalten.',
      name: 'Sonderzeichen'
    },
    specialCharactersReplacement: {
      description: 'Ersetzungsstring für Sonderzeichen in Anhang-Ordner und Dateiname.\nLeer lassen, um Sonderzeichen zu entfernen.',
      name: 'Sonderzeichen-Ersetzung'
    },
    timeoutInSeconds: {
      description: 'Das Timeout in Sekunden für alle Operationen.\nWenn {{zero}} gesetzt ist, ist das Ausführungs-Timeout für Operationen deaktiviert.',
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
