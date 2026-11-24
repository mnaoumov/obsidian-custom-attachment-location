export const no = {
  attachmentCollector: {
    confirm: 'Vil du samle vedlegg for alle notater i mappene rekursivt?\n{{folders}}\nDenne operasjonen kan ikke angres.',
    progressBar: {
      message: 'Samler vedlegg {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Samler vedlegg...'
    }
  },
  buttons: {
    copy: 'Kopier',
    move: 'Flytt',
    previewAttachmentFile: 'Forhåndsvisning av vedleggsfil',
    skip: 'Hopp over'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Vedlegget {{attachment}} refereres av flere notater.',
    heading: 'Samler vedlegg brukt av flere notater',
    noPriorityWinnerReason: {
      EmptyList: 'Det ble ikke flyttet fordi innstillingen {{settingName}} er tom, så ingenting avgjør hvilket av disse notatene som eier det.',
      NoMatch: 'Det ble ikke flyttet fordi ingen av disse notatene samsvarer med noen oppføring i innstillingen {{settingName}}.',
      Tie: 'Det ble ikke flyttet fordi flere av disse notatene samsvarer like godt med innstillingen {{settingName}}, så den utpeker ingen enkelt eier.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Bør bruke samme handling for andre problematiske vedlegg'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Samle vedlegg i gjeldende mappe',
    collectAttachmentsCurrentNote: 'Samle vedlegg i gjeldende notat',
    collectAttachmentsEntireVault: 'Samle vedlegg i hele krypteret'
  },
  links: {
    documentation: 'dokumentasjonen',
    tokens: 'tokens'
  },
  menuItems: {
    collectAttachmentsInFile: 'Samle vedlegg i fil',
    collectAttachmentsInFiles: 'Samle vedlegg i filer'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Samler vedlegg for \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Innsamling av vedlegg avbrutt. Se konsoll for detaljer.',
    generatedAttachmentFileNameIsInvalid: 'Generert vedleggsfilnavn \'{{path}}\' er ugyldig.\n{{validationMessage}}\nSjekk innstillingen {{settingName}}.',
    notePathIsIgnored: 'Notatbane ignoreres'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Avbryt',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Elementer per side:',
      jumpToPage: 'Gå til side:'
    },
    notices: {
      attachmentIsStillUsed: 'Vedlegg {{attachmentPath}} brukes fortsatt av andre notater. Det vil ikke bli slettet.',
      unhandledError: 'En uhåndtert feil oppstod. Vennligst sjekk konsollen for mer informasjon.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'alle filer omdøpes.',
        displayText: 'Alle'
      },
      none: {
        description: 'navnene deres bevares.',
        displayText: 'Ingen'
      },
      onlyPastedImages: {
        description: 'bare innlimte bilder omdøpes. Gjelder bare når PNG-bildeinnhold limes inn fra utklippstavlen direkte. Vanligvis for å lime inn skjermbilder.',
        displayText: 'Bare innlimte bilder'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'avbryt vedleggsinnsamlingen.',
        displayText: 'Avbryt'
      },
      copy: {
        description: 'kopier vedlegget til den nye plasseringen.',
        displayText: 'Kopier'
      },
      move: {
        description: 'flytt vedlegget til den nye plasseringen.',
        displayText: 'Flytt'
      },
      prompt: {
        description: 'spør brukeren om å velge handlingen.',
        displayText: 'Spør'
      },
      skip: {
        description: 'hopp over vedlegget og gå videre til neste.',
        displayText: 'Hopp over'
      }
    },
    defaultImageSizeDimension: {
      height: 'Høyde',
      width: 'Bredde'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Tilpassede tokens ble kommentert ut da de må oppdateres til det nye formatet introdusert i plugin versjon 9.0.0.\n// Se dokumentasjonen ({{customTokensDocumentationUrl}}) for mer informasjon.',
      deprecated: 'Formatet for registrering av tilpassede tokens er endret. Oppdater tokens dine tilsvarende. Se {{documentation}} for mer informasjon.'
    },
    legacyRenameAttachmentsToLowerCase: 'Innstillingen {{setting}} er utdatert. Bruk formatet {{format}} i stedet. Se {{documentation}} for mer informasjon.',
    markdownUrlFormat: {
      deprecated: 'Du har muligens satt en feil verdi for formatet {{setting}}. Se {{documentation}} for mer informasjon. Denne meldingen vil ikke vises igjen.'
    },
    specialCharacters: 'Standardverdien for innstillingen {{setting}} er endret. Innstillingsverdien din ble oppdatert til den nye standardverdien.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Standard bildestørrelse må være i piksler eller prosent',
      invalidCustomTokensCode: 'Ugyldig tilpasset tokens kode',
      invalidRegularExpression: 'Ugyldig regulært uttrykk {{regExp}}',
      specialCharactersMustNotContainSlash: 'Spesialtegn må ikke inneholde /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Spesialtegnerstatning må ikke inneholde ugyldige filnavn stibokstaver.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Når du legger ved filer:',
      name: 'Vedlegg omdøpingsmodus'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Når det innsamlede vedlegget brukes av flere notater:',
      name: 'Samle vedlegg brukt av flere notater modus'
    },
    collectedAttachmentFileName: {
      description: 'Se tilgjengelige {{tokens}}.\nLa stå tom for å beholde vedleggets nåværende filnavn.',
      name: 'Samlet vedleggsfilnavn'
    },
    customTokens: {
      description: 'Tilpassede tokens som skal brukes.\nSe {{documentation}} for mer informasjon.\n⚠️ Tilpassede tokens kan være vilkårlig JavaScript-kode. Hvis den er dårlig skrevet, kan den føre til tap av data. Bruk dem på egen risiko.',
      name: 'Tilpassede tokens'
    },
    defaultImageSize: {
      description: 'Standard bildestørrelse.\nKan angis i piksler ({{pixels}}) eller i prosent av hele bildestørrelsen ({{percentage}}).\nLa stå tom for å bruke original bildestørrelse.',
      name: 'Standard bildestørrelse'
    },
    duplicateNameSeparator: {
      description: 'Når du limer inn eller drar en fil med samme navn som en eksisterende fil, legges denne separatoren til filnavnet.\nF.eks. når du drar filen {{existingFile}}, omdøpes den til {{firstAvailableName}}, {{secondAvailableName}} osv., og får det første tilgjengelige navnet.',
      name: 'Duplikat navn separator'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Ekskluder vedlegg fra følgende stier når kommandoen {{command}} utføres.\nSett inn hver sti på en ny linje.\n{{pathSyntax}}\nHvis innstillingen er tom, ekskluderes ingen stier fra vedleggsinnsamling.',
      name: 'Ekskluder stier fra vedleggsinnsamling'
    },
    generatedAttachmentFileName: {
      description: 'Se tilgjengelige {{tokens}}.',
      name: 'Generert vedleggsfilnavn'
    },
    jpegQuality: {
      description: 'Jo mindre kvalitet, jo større komprimeringsforhold.',
      name: 'JPEG Kvalitet'
    },
    locationForNewAttachments: {
      description: 'Start med {{relativePrefix}} for stier relativt til notatets overordnede mappe.\nSe tilgjengelige {{tokens}}.\nPunktmapper som {{dotFolder}} anbefales ikke, fordi Obsidian ikke sporer dem. Du må kanskje bruke programtillegget {{unhidePlugin}} for å administrere dem.',
      name: 'Plassering for nye vedlegg'
    },
    markdownUrlFormat: {
      description: 'Format for URL-en som settes inn i Markdown når et vedlegg legges til. Det brukes bare i det øyeblikket: en lenke som Obsidian skriver om senere, når et notat eller et vedlegg får nytt navn eller flyttes, får standardformatet.\nSe tilgjengelige {{tokens}}.\nLa stå tom for å bruke standardformatet.',
      name: 'Markdown URL format'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Om innstillingene for vedleggsmappe og filnavn skal brukes på vedlegg som ANDRE programtillegg oppretter.\nNoen programtillegg skriver et vedlegg inn i hvelvet under sitt eget navn, uten å spørre Obsidian hvor det hører hjemme. Er dette slått på, blir en slik fil flyttet og gitt nytt navn straks den dukker opp.\nBare filer som opprettes mens et notat er åpent, og som et notat lenker til, berøres: en fil som ingen notater lenker til, er data et annet programtillegg holder for seg selv, og blir liggende der den ble skrevet. Filer som kommer fra en synkronisering eller en hvelvimport, berøres aldri.\n{{modes}}\nProgramtillegget som oppretter filen, identifiseres fra kallstakken til skrivingen. Det skjer etter beste evne: ingen programtillegg identifiseres for en fil skrevet av Obsidian selv, av en synkroniseringsklient eller av et programtillegg som utsetter skrivingen. En slik fil regnes som IKKE å være i listen nedenfor.',
      name: 'Gi nytt navn til vedlegg opprettet av andre programtillegg'
    },
    renameAttachmentsToLowerCase: 'Omdøp vedlegg til små bokstaver',
    renamedAttachmentFileName: {
      description: 'Se tilgjengelige {{tokens}}.\nLa stå tom for å beholde vedleggets nåværende filnavn.',
      name: 'Omdøpt vedleggsfilnavn'
    },
    resetToSampleCustomTokens: {
      message: 'Er du sikker på at du vil tilbakestille de tilpassede tokens til eksempel tilpassede tokens? Endringene dine vil gå tapt.',
      title: 'Tilbakestill til eksempel tilpassede tokens'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Om innlimte bilder skal konverteres til JPEG. Gjelder bare når PNG-bildeinnhold limes inn fra utklippstavlen direkte. Vanligvis for å lime inn skjermbilder.',
      name: 'Skal konvertere innlimte bilder til JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Hvis aktivert, vil vedlegg som behandles via kommandoene {{command}}, omdøpes i henhold til innstillingen {{setting}}.',
      name: 'Skal omdøpe innsamlede vedlegg'
    },
    specialCharacters: {
      description: 'Spesialtegn i vedleggsmappe og filnavn som skal erstattes eller fjernes.\nLa stå tom for å bevare spesialtegn.',
      name: 'Spesialtegn'
    },
    specialCharactersReplacement: {
      description: 'Erstatningsstreng for spesialtegn i vedleggsmappe og filnavn.\nLa stå tom for å fjerne spesialtegn.',
      name: 'Spesialtegnerstatning'
    },
    timeoutInSeconds: {
      description: 'Tidsavbrudd i sekunder for alle operasjoner.\nHvis {{zero}} er satt, er tidsavbruddet for operasjonsutførelse deaktivert.',
      name: 'Tidsavbrudd i sekunder'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Gi vedleggsfilen nytt navn',
    folderTitle: 'Velg vedleggsmappe',
    previewModal: {
      title: 'Forhåndsvisning av vedleggsfil \'{{fullFileName}}\''
    },
    title: 'Oppgi en verdi for prompt token'
  },
  regularExpression: '/regulært uttrykk/'
};
