export const da = {
  attachmentCollector: {
    confirm: 'Vil du indsamle vedhæftninger for alle noter i mapper rekursivt?\n{{folders}}\nDenne handling kan ikke fortrydes.',
    progressBar: {
      message: 'Samler vedhæftninger {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Samler vedhæftninger...'
    }
  },
  buttons: {
    copy: 'Kopier',
    move: 'Flyt',
    previewAttachmentFile: 'Forhåndsvis vedhæftningsfil',
    skip: 'Spring over'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Vedhæftningen {{attachment}} refereres af flere noter.',
    heading: 'Samler vedhæftning brugt af flere noter',
    noPriorityWinnerReason: {
      EmptyList: 'Den blev ikke flyttet, fordi indstillingen {{settingName}} er tom, så intet afgør, hvilken af disse noter der ejer den.',
      NoMatch: 'Den blev ikke flyttet, fordi ingen af disse noter matcher nogen post i indstillingen {{settingName}}.',
      Tie: 'Den blev ikke flyttet, fordi flere af disse noter matcher indstillingen {{settingName}} lige godt, så den udpeger ingen enkelt ejer.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Skal bruge samme handling for andre problematiske vedhæftninger'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Saml vedhæftninger i nuværende mappe',
    collectAttachmentsCurrentNote: 'Saml vedhæftninger i nuværende note',
    collectAttachmentsEntireVault: 'Saml vedhæftninger i hele vault'
  },
  links: {
    documentation: 'dokumentationen',
    tokens: 'tokens'
  },
  menuItems: {
    collectAttachmentsInFile: 'Indsaml vedhæftninger i fil',
    collectAttachmentsInFiles: 'Indsaml vedhæftninger i filer'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Samler vedhæftninger for \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Samling af vedhæftninger annulleret. Se konsol for detaljer.',
    generatedAttachmentFileNameIsInvalid: 'Genereret vedhæftningsfilnavn \'{{path}}\' er ugyldigt.\n{{validationMessage}}\nTjek din indstilling {{settingName}}.',
    notePathIsIgnored: 'Notesti er ignoreret'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Annuller',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Elementer per side:',
      jumpToPage: 'Hop til side:'
    },
    notices: {
      attachmentIsStillUsed: 'Vedhæftning {{attachmentPath}} bruges stadig af andre noter. Den vil ikke blive slettet.',
      unhandledError: 'Der opstod en ubehandlet fejl. Tjek venligst konsollen for flere oplysninger.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'alle filer omdøbes.',
        displayText: 'Alle'
      },
      none: {
        description: 'deres navne bevares.',
        displayText: 'Ingen'
      },
      onlyPastedImages: {
        description: 'kun indsatte billeder omdøbes. Gælder kun når PNG-billedindholdet indsættes direkte fra udklipsholderen. Typisk til indsættelse af skærmbilleder.',
        displayText: 'Kun indsatte billeder'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'annuller samling af vedhæftninger.',
        displayText: 'Annuller'
      },
      copy: {
        description: 'kopier vedhæftningen til den nye placering.',
        displayText: 'Kopier'
      },
      move: {
        description: 'flyt vedhæftningen til den nye placering.',
        displayText: 'Flyt'
      },
      prompt: {
        description: 'bed brugeren om at vælge handlingen.',
        displayText: 'Anmodning'
      },
      skip: {
        description: 'spring vedhæftningen over og fortsæt til den næste.',
        displayText: 'Spring over'
      }
    },
    defaultImageSizeDimension: {
      height: 'Højde',
      width: 'Bredde'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Brugerdefinerede tokens blev kommenteret ud, da de skal opdateres til det nye format introduceret i plugin version 9.0.0.\n// Se dokumentationen ({{customTokensDocumentationUrl}}) for flere oplysninger.',
      deprecated: 'Formatet for registrering af brugerdefinerede tokens er ændret. Opdater venligst dine tokens i overensstemmelse hermed. Se {{documentation}} for flere oplysninger.'
    },
    legacyRenameAttachmentsToLowerCase: 'Indstillingen {{setting}} er forældet. Brug formatet {{format}} i stedet. Se {{documentation}} for flere oplysninger.',
    markdownUrlFormat: {
      deprecated: 'Du har muligvis sat en forkert værdi for formatet {{setting}}. Se {{documentation}} for flere oplysninger. Denne besked vil ikke blive vist igen.'
    },
    specialCharacters: 'Standardværdien for indstillingen {{setting}} er ændret. Din indstillingsværdi er blevet opdateret til den nye standardværdi.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Standardbilledstørrelsen skal angives i pixels eller procent',
      invalidCustomTokensCode: 'Ugyldig brugerdefineret tokens-kode',
      invalidRegularExpression: 'Ugyldigt regulært udtryk {{regExp}}',
      specialCharactersMustNotContainSlash: 'Særlige tegn må ikke indeholde /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Erstatning af særlige tegn må ikke indeholde ugyldige filnavnsti-tegn.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Når der vedhæftes filer:',
      name: 'Vedhæftningsomdøbningstilstand'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Når den samlede vedhæftning bruges af flere noter:',
      name: 'Saml vedhæftning brugt af flere noter tilstand'
    },
    collectedAttachmentFileName: {
      description: 'Se tilgængelige {{tokens}}.\nLad stå tomt for at beholde det nuværende vedhæftningsfilnavn.',
      name: 'Samlet vedhæftningsfilnavn'
    },
    customTokens: {
      description: 'Brugerdefinerede tokens der skal bruges.\nSe {{documentation}} for flere oplysninger.\n⚠️ Brugerdefinerede tokens kan være vilkårlig JavaScript-kode. Hvis de er dårligt skrevet, kan de forårsage datatab. Brug dem på egen risiko.',
      name: 'Brugerdefinerede tokens'
    },
    defaultImageSize: {
      description: 'Standardbilledstørrelsen.\nKan angives i pixels ({{pixels}}) eller i procent af den fulde billedstørrelse ({{percentage}}).\nLad stå tomt for at bruge den originale billedstørrelse.',
      name: 'Standardbilledstørrelse'
    },
    duplicateNameSeparator: {
      description: 'Når du indsætter/trækker en fil med samme navn som en eksisterende fil, vil denne separator blive tilføjet til filnavnet.\nF.eks., når du trækker filen {{existingFile}}, vil den blive omdøbt til {{firstAvailableName}}, {{secondAvailableName}} osv., alt efter hvilket navn der først er ledigt.',
      name: 'Duplikatnavnseparator'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Udeluk vedhæftninger fra følgende stier, når kommandoen {{command}} udføres.\nIndsæt hver sti på en ny linje.\n{{pathSyntax}}\nHvis indstillingen er tom, udelukkes ingen stier fra vedhæftningssamling.',
      name: 'Udeluk stier fra vedhæftningssamling'
    },
    generatedAttachmentFileName: {
      description: 'Se tilgængelige {{tokens}}.',
      name: 'Genereret vedhæftningsfilnavn'
    },
    jpegQuality: {
      description: 'Jo mindre kvaliteten, jo større kompressionsforhold.',
      name: 'JPEG-kvalitet'
    },
    locationForNewAttachments: {
      description: 'Start med {{relativePrefix}} for stier relative til notens overordnede mappe.\nSe tilgængelige {{tokens}}.\nPunktmapper som {{dotFolder}} anbefales ikke, fordi Obsidian ikke sporer dem. Du skal muligvis bruge pluginet {{unhidePlugin}} til at administrere dem.',
      name: 'Placering for nye vedhæftninger'
    },
    markdownUrlFormat: {
      description: 'Format for URL\'en, der vil blive indsat i Markdown, når en vedhæftning tilføjes. Det anvendes kun i det øjeblik: et link, som Obsidian senere omskriver, når en note eller en vedhæftning omdøbes eller flyttes, får standardformatet.\nSe tilgængelige {{tokens}}.\nLad stå tomt for at bruge standardformatet.',
      name: 'Markdown URL-format'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Om indstillingerne for vedhæftningsmappe og filnavn skal anvendes på vedhæftninger, som ANDRE plugins opretter.\nNogle plugins skriver en vedhæftning direkte i boksen under deres eget navn uden at spørge Obsidian, hvor den hører hjemme. Med dette slået til flyttes og omdøbes en sådan fil, så snart den dukker op.\nKun filer, der oprettes, mens en note er åben, og som en note linker til, berøres: en fil, som ingen note linker til, er data, som et andet plugin gemmer til sig selv, og den bliver, hvor den blev skrevet. Filer, der kommer fra en synkronisering eller en boks-import, berøres aldrig.\n{{modes}}\nDet plugin, der opretter filen, identificeres ud fra skrivningens kaldstak. Det sker efter bedste evne: der identificeres intet plugin for en fil skrevet af Obsidian selv, af en synkroniseringsklient eller af et plugin, der udskyder sin skrivning. En sådan fil regnes for IKKE at være på listen nedenfor.',
      name: 'Omdøb vedhæftninger oprettet af andre plugins'
    },
    renameAttachmentsToLowerCase: 'Omdøb vedhæftninger til små bogstaver',
    renamedAttachmentFileName: {
      description: 'Se tilgængelige {{tokens}}.\nLad stå tomt for at beholde det nuværende vedhæftningsfilnavn.',
      name: 'Omdøbt vedhæftningsfilnavn'
    },
    resetToSampleCustomTokens: {
      message: 'Er du sikker på, at du vil nulstille de brugerdefinerede tokens til de eksempel-brugerdefinerede tokens? Dine ændringer vil gå tabt.',
      title: 'Nulstil til eksempel-brugerdefinerede tokens'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Om indsatte billeder skal konverteres til JPEG. Gælder kun når PNG-billedindholdet indsættes direkte fra udklipsholderen. Typisk til indsættelse af skærmbilleder.',
      name: 'Skal konvertere indsatte billeder til JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Hvis aktiveret, vil vedhæftninger behandlet via kommandoerne {{command}} blive omdøbt i henhold til indstillingen {{setting}}.',
      name: 'Skal omdøbe samlede vedhæftninger'
    },
    specialCharacters: {
      description: 'Særlige tegn i vedhæftningsmappe- og filnavn, der skal erstattes eller fjernes.\nLad stå tomt for at bevare særlige tegn.',
      name: 'Særlige tegn'
    },
    specialCharactersReplacement: {
      description: 'Erstatningsstreng for særlige tegn i vedhæftningsmappe- og filnavn.\nLad stå tomt for at fjerne særlige tegn.',
      name: 'Særlige tegn-erstatning'
    },
    timeoutInSeconds: {
      description: 'Timeout i sekunder for alle operationer.\nHvis {{zero}} er sat, er operationernes udførelsestimeout deaktiveret.',
      name: 'Timeout i sekunder'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Omdøb vedhæftningsfil',
    folderTitle: 'Vælg vedhæftningsmappe',
    previewModal: {
      title: 'Forhåndsvis vedhæftningsfil \'{{fullFileName}}\''
    },
    title: 'Angiv en værdi for prompt-tokenet'
  },
  regularExpression: '/regulært udtryk/'
};
