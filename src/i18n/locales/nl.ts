export const nl = {
  attachmentCollector: {
    confirm: 'Wil je bijlagen voor alle notities in de mappen recursief verzamelen?\n{{folders}}\nDeze bewerking kan niet ongedaan worden gemaakt.',
    progressBar: {
      message: 'Bijlagen verzamelen {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Bijlagen verzamelen...'
    }
  },
  buttons: {
    copy: 'Kopiëren',
    move: 'Verplaatsen',
    previewAttachmentFile: 'Voorvertoning bijlagebestand',
    skip: 'Overslaan'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Naar bijlage {{attachment}} wordt verwezen door meerdere notities.',
    heading: 'Bijlage verzamelen die door meerdere notities wordt gebruikt',
    noPriorityWinnerReason: {
      EmptyList: 'Het is niet verplaatst omdat de instelling {{settingName}} leeg is, dus niets bepaalt welke van deze notities het bezit.',
      NoMatch: 'Het is niet verplaatst omdat geen van deze notities overeenkomt met een vermelding in de instelling {{settingName}}.',
      Tie: 'Het is niet verplaatst omdat meerdere van deze notities even goed overeenkomen met de instelling {{settingName}}, waardoor die geen enkele eigenaar aanwijst.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Dezelfde actie gebruiken voor andere problematische bijlagen'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Bijlagen verzamelen in huidige map',
    collectAttachmentsCurrentNote: 'Bijlagen verzamelen in huidige notitie',
    collectAttachmentsEntireVault: 'Bijlagen verzamelen in hele kluis'
  },
  links: {
    documentation: 'documentatie',
    tokens: 'tokens'
  },
  menuItems: {
    collectAttachmentsInFile: 'Bijlagen verzamelen in bestand',
    collectAttachmentsInFiles: 'Bijlagen verzamelen in bestanden'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Bijlagen verzamelen voor \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Bijlagen verzamelen geannuleerd. Zie console voor details.',
    generatedAttachmentFileNameIsInvalid: 'Gegenereerde bijlagebestandsnaam \'{{path}}\' is ongeldig.\n{{validationMessage}}\nControleer je instelling {{settingName}}.',
    notePathIsIgnored: 'Notitie pad wordt genegeerd'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Annuleren',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Items per pagina:',
      jumpToPage: 'Ga naar pagina:'
    },
    notices: {
      attachmentIsStillUsed: 'Bijlage {{attachmentPath}} wordt nog steeds gebruikt door andere notities. Deze wordt niet verwijderd.',
      unhandledError: 'Er is een onverwerkte fout opgetreden. Controleer de console voor meer informatie.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'alle bestanden worden hernoemd.',
        displayText: 'Alle'
      },
      none: {
        description: 'hun namen worden behouden.',
        displayText: 'Geen'
      },
      onlyPastedImages: {
        description: 'alleen geplakte afbeeldingen worden hernoemd. Geldt alleen wanneer PNG afbeeldingsinhoud direct vanuit het klembord wordt geplakt. Meestal voor het plakken van screenshots.',
        displayText: 'Alleen geplakte afbeeldingen'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'annuleer het verzamelen van bijlagen.',
        displayText: 'Annuleren'
      },
      copy: {
        description: 'kopieer de bijlage naar de nieuwe locatie.',
        displayText: 'Kopiëren'
      },
      move: {
        description: 'verplaats de bijlage naar de nieuwe locatie.',
        displayText: 'Verplaatsen'
      },
      prompt: {
        description: 'vraag de gebruiker om de actie te kiezen.',
        displayText: 'Vragen'
      },
      skip: {
        description: 'sla de bijlage over en ga door naar de volgende.',
        displayText: 'Overslaan'
      }
    },
    defaultImageSizeDimension: {
      height: 'Hoogte',
      width: 'Breedte'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Aangepaste tokens zijn uitgecommentarieerd omdat ze moeten worden bijgewerkt naar het nieuwe formaat geïntroduceerd in plugin versie 9.0.0.\n// Raadpleeg de documentatie ({{customTokensDocumentationUrl}}) voor meer informatie.',
      deprecated: 'Het formaat voor het registreren van aangepaste tokens is veranderd. Werk je tokens dienovereenkomstig bij. Raadpleeg de {{documentation}} voor meer informatie.'
    },
    legacyRenameAttachmentsToLowerCase: 'De instelling {{setting}} is verouderd. Gebruik in plaats daarvan het formaat {{format}}. Zie de {{documentation}} voor meer informatie.',
    markdownUrlFormat: {
      deprecated: 'Je hebt mogelijk een onjuiste waarde ingesteld voor het formaat {{setting}}. Raadpleeg de {{documentation}} voor meer informatie. Dit bericht wordt niet meer getoond.'
    },
    specialCharacters: 'De standaardwaarde van de instelling {{setting}} is veranderd. Je instellingswaarde is bijgewerkt naar de nieuwe standaardwaarde.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'De standaardafmeting van de afbeelding moet in pixels of procenten zijn',
      invalidCustomTokensCode: 'Ongeldige aangepaste tokens code',
      invalidRegularExpression: 'Ongeldige reguliere expressie {{regExp}}',
      specialCharactersMustNotContainSlash: 'Speciale karakters mogen geen / bevatten',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Speciale karakter vervanging mag geen ongeldige bestandsnaam pad karakters bevatten.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Bij het bijvoegen van bestanden:',
      name: 'Bijlage hernoem modus'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Wanneer de verzamelde bijlage door meerdere notities wordt gebruikt:',
      name: 'Verzamel bijlage gebruikt door meerdere notities modus'
    },
    collectedAttachmentFileName: {
      description: 'Zie beschikbare {{tokens}}.\nLaat leeg om de huidige bestandsnaam van de bijlage te behouden.',
      name: 'Verzamelde bijlage bestandsnaam'
    },
    customTokens: {
      description: 'Aangepaste tokens om te gebruiken.\nZie de {{documentation}} voor meer informatie.\n⚠️ Aangepaste tokens kunnen willekeurige JavaScript-code zijn. Als ze slecht geschreven zijn, kunnen ze gegevensverlies veroorzaken. Gebruik ze op eigen risico.',
      name: 'Aangepaste tokens'
    },
    defaultImageSize: {
      description: 'De standaardafmeting van de afbeelding.\nKan worden opgegeven in pixels ({{pixels}}) of als percentage van de volledige afbeeldingsgrootte ({{percentage}}).\nLaat leeg om de originele afbeeldingsgrootte te gebruiken.',
      name: 'Standaardafmeting afbeelding'
    },
    duplicateNameSeparator: {
      description: 'Wanneer je een bestand plakt of sleept met dezelfde naam als een bestaand bestand, wordt dit scheidingsteken aan de bestandsnaam toegevoegd.\nBijv. wanneer je het bestand {{existingFile}} sleept, wordt het hernoemd naar {{firstAvailableName}}, {{secondAvailableName}}, enz., waarbij de eerste beschikbare naam wordt gebruikt.',
      name: 'Dubbele naam scheidingsteken'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Sluit bijlagen uit de volgende paden uit wanneer het commando {{command}} wordt uitgevoerd.\nVoeg elk pad toe op een nieuwe regel.\n{{pathSyntax}}\nAls de instelling leeg is, worden geen paden uitgesloten van het verzamelen van bijlagen.',
      name: 'Uitgesloten paden van bijlage verzamelen'
    },
    generatedAttachmentFileName: {
      description: 'Zie beschikbare {{tokens}}.',
      name: 'Gegenereerde bijlage bestandsnaam'
    },
    jpegQuality: {
      description: 'Hoe kleiner de kwaliteit, hoe groter de compressieverhouding.',
      name: 'JPEG Kwaliteit'
    },
    locationForNewAttachments: {
      description: 'Begin met {{relativePrefix}} voor paden relatief aan de bovenliggende map van de notitie.\nZie beschikbare {{tokens}}.\nPuntmappen zoals {{dotFolder}} worden niet aanbevolen, omdat Obsidian ze niet bijhoudt. Mogelijk heb je de plugin {{unhidePlugin}} nodig om ze te beheren.',
      name: 'Locatie voor nieuwe bijlagen'
    },
    markdownUrlFormat: {
      description: 'Formaat voor de URL die in Markdown wordt ingevoegd wanneer een bijlage wordt toegevoegd. Het wordt alleen op dat moment toegepast: een link die Obsidian later herschrijft, wanneer een notitie of bijlage wordt hernoemd of verplaatst, krijgt het standaardformaat.\nZie beschikbare {{tokens}}.\nLaat leeg om het standaardformaat te gebruiken.',
      name: 'Markdown URL formaat'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description:
        'Of de instellingen voor bijlagemap en bestandsnaam ook gelden voor bijlagen die ANDERE plug-ins aanmaken.\nSommige plug-ins schrijven een bijlage onder een eigen naam in de kluis, zonder Obsidian te vragen waar die hoort. Staat dit aan, dan wordt zo\'n bestand meteen na het verschijnen verplaatst en hernoemd.\nAlleen bestanden die ontstaan terwijl een notitie open is en waarnaar een notitie linkt, worden aangeraakt: een bestand waarnaar geen notitie linkt, bevat gegevens die een andere plug-in voor zichzelf bewaart, en blijft waar het is geschreven. Bestanden uit een synchronisatie of een kluisimport worden nooit aangeraakt.\n{{modes}}\nDe plug-in die het bestand aanmaakt, wordt bepaald aan de hand van de aanroepstack van de schrijfbewerking. Dat gebeurt naar beste vermogen: er wordt geen plug-in herkend voor een bestand dat Obsidian zelf, een synchronisatieclient of een plug-in die zijn schrijfbewerking uitstelt heeft geschreven. Zo\'n bestand telt als NIET in de onderstaande lijst.',
      name: 'Bijlagen hernoemen die andere plug-ins aanmaken'
    },
    renameAttachmentsToLowerCase: 'Hernoem bijlagen naar kleine letters',
    renamedAttachmentFileName: {
      description: 'Zie beschikbare {{tokens}}.\nLaat leeg om de huidige bestandsnaam van de bijlage te behouden.',
      name: 'Hernoemde bijlage bestandsnaam'
    },
    resetToSampleCustomTokens: {
      message: 'Weet je zeker dat je de aangepaste tokens wilt resetten naar de voorbeeld aangepaste tokens? Je wijzigingen gaan verloren.',
      title: 'Reset naar voorbeeld aangepaste tokens'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Of geplakte afbeeldingen moeten worden geconverteerd naar JPEG. Geldt alleen wanneer PNG afbeeldingsinhoud direct vanuit het klembord wordt geplakt. Meestal voor het plakken van screenshots.',
      name: 'Moet geplakte afbeeldingen converteren naar JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Indien ingeschakeld, worden bijlagen die via de commando\'s {{command}} worden verwerkt, hernoemd volgens de instelling {{setting}}.',
      name: 'Moet verzamelde bijlagen hernoemen'
    },
    specialCharacters: {
      description: 'Speciale karakters in de bijlagemap en bestandsnaam die moeten worden vervangen of verwijderd.\nLaat leeg om speciale karakters te behouden.',
      name: 'Speciale karakters'
    },
    specialCharactersReplacement: {
      description: 'Vervangingsstring voor speciale karakters in de bijlagemap en bestandsnaam.\nLaat leeg om speciale karakters te verwijderen.',
      name: 'Speciale karakters vervanging'
    },
    timeoutInSeconds: {
      description: 'De timeout in seconden voor alle bewerkingen.\nAls {{zero}} is ingesteld, is de uitvoeringstimeout van bewerkingen uitgeschakeld.',
      name: 'Timeout in seconden'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Bijlagebestand hernoemen',
    folderTitle: 'Bijlagemap kiezen',
    previewModal: {
      title: 'Voorvertoning bijlage bestand \'{{fullFileName}}\''
    },
    title: 'Geef een waarde voor de prompt token'
  },
  regularExpression: '/reguliere expressie/'
};
