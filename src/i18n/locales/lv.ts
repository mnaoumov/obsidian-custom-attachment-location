export const lv = {
  attachmentCollector: {
    confirm: 'Vai vēlaties rekursīvi savākt pielikumus visām piezīmēm šajās mapēs?\n{{folders}}\nŠo darbību nevar atsaukt.',
    progressBar: {
      message: 'Apkopoju pielikumus {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Apkopoju pielikumus...'
    }
  },
  buttons: {
    copy: 'Kopēt',
    move: 'Pārvietot',
    previewAttachmentFile: 'Pielikuma faila priekšskatījums',
    skip: 'Izlaist'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Uz pielikumu {{attachment}} atsaucas vairākas piezīmes.',
    heading: 'Apkopoju pielikumu, kuru lieto vairākas piezimes',
    noPriorityWinnerReason: {
      EmptyList: 'Tas netika pārvietots, jo iestatījums {{settingName}} ir tukšs, tāpēc nekas nenosaka, kurai no šīm piezīmēm tas pieder.',
      NoMatch: 'Tas netika pārvietots, jo neviena no šīm piezīmēm neatbilst nevienam ierakstam iestatījumā {{settingName}}.',
      Tie: 'Tas netika pārvietots, jo vairākas no šīm piezīmēm vienlīdz labi atbilst iestatījumam {{settingName}}, tāpēc tas nenosauc vienu īpašnieku.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Izmantot to pašu darbību citiem problēmatiskajiem pielikumiem'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Apkopot pielikumus pšreizējā mappē',
    collectAttachmentsCurrentNote: 'Apkopot pielikumus pšreizējā piezimē',
    collectAttachmentsEntireVault: 'Apkopot pielikumus visā glabatavā'
  },
  links: {
    documentation: 'dokumentācijā',
    tokens: 'tokenus'
  },
  menuItems: {
    collectAttachmentsInFile: 'Savākt pielikumus failā',
    collectAttachmentsInFiles: 'Savākt pielikumus failos'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Apkopoju pielikumus priekš \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Pielikumu apkopošana atcelta. Skatiet konsoli detalām.',
    generatedAttachmentFileNameIsInvalid: 'Ģenerētais pielikuma faila nosaukums \'{{path}}\' nav derīgs.\n{{validationMessage}}\nPārbaudiet iestatījumu {{settingName}}.',
    notePathIsIgnored: 'Piezimes ceļš tiek ignorēts'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Atcelt',
      ok: 'Labi'
    },
    dataview: {
      itemsPerPage: 'Vienumi lapā:',
      jumpToPage: 'Pāriet uz lapu:'
    },
    notices: {
      attachmentIsStillUsed: 'Pielikums {{attachmentPath}} joprojām tiek izmantots citās piezimēs. Tas netiks dzēsts.',
      unhandledError: 'Radās neapstrādāta kļūda. Lūdzu, pārbaudiet konsoli, lai iegūtu vairāk informācijas.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'visi faili tiek pārdēvēti.',
        displayText: 'Visi'
      },
      none: {
        description: 'to nosaukumi tiek saglabāti.',
        displayText: 'Neviens'
      },
      onlyPastedImages: {
        description: 'tikai ielīmētās attēli tiek pārdēvēti. Attiecas tikai tad, kad PNG attēla saturs tiek ielīmēts tieši no starpliktuvnes. Parasti ekrānuzņēmumu ielīmēšanai.',
        displayText: 'Tikai ielīmētie attēli'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'atcelt pielikumu apkopošanu.',
        displayText: 'Atcelt'
      },
      copy: {
        description: 'kopēt pielikumu uz jauno atrašanās vietu.',
        displayText: 'Kopēt'
      },
      move: {
        description: 'pārvietot pielikumu uz jauno atrašanās vietu.',
        displayText: 'Pārvietot'
      },
      prompt: {
        description: 'prasīt lietotājam izvēlēties darbību.',
        displayText: 'Prasīt'
      },
      skip: {
        description: 'izlaist pielikumu un turpināt ar nākamo.',
        displayText: 'Izlaist'
      }
    },
    defaultImageSizeDimension: {
      height: 'Augstums',
      width: 'Platums'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Pielāgotie tokeni tika komentēti, jo tie ir jāatjaunina uz jauno formātu, kas ieviests spraudņa versijā 9.0.0.\n// Sīkāku informāciju skatiet dokumentācijā ({{customTokensDocumentationUrl}}).',
      deprecated: 'Pielāgoto tokenu reģistrācijas formāts ir mainījies. Lūdzu, attiecīgi atjauniniet savus tokenus. Sīkāku informāciju skatiet {{documentation}}.'
    },
    legacyRenameAttachmentsToLowerCase: 'Iestatījums {{setting}} ir novecojis. Tā vietā izmantojiet formātu {{format}}. Sīkāku informāciju skatiet {{documentation}}.',
    markdownUrlFormat: {
      deprecated: 'Jums, iespējams, ir iestatīta nepareiza vērtība formātam {{setting}}. Sīkāku informāciju, lūdzu, skatiet {{documentation}}. Šis ziņojums vairs netiks parādīts.'
    },
    specialCharacters: 'Iestatījuma {{setting}} noklusējuma vērtība ir mainījusies. Jūsu iestatījuma vērtība tika atjaunināta uz jauno noklusējuma vērtību.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Noklusējuma attēla izmēram jābūt pikseļos vai procentos',
      invalidCustomTokensCode: 'Nederīgs pielāgoto tokenu kods',
      invalidRegularExpression: 'Nederīga regulārā izteiksme {{regExp}}',
      specialCharactersMustNotContainSlash: 'Īpašajos rakstzīmēs nedrīkst būt /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Īpašo rakstzīmju aizstāšana nedrīkst saturēt nederīgus faila nosaukuma ceļa rakstzīmes.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Pievienojot failus:',
      name: 'Pielikuma pārdēvēšanas režīms'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Kad apkopotais pielikums tiek izmantots vairākās piezīmēs:',
      name: 'Vairākās piezimēs izmantoto pielikumu apkopošanas režīms'
    },
    collectedAttachmentFileName: {
      description: 'Skatiet pieejamos {{tokens}}.\nAtstājiet tukšu, lai saglabātu pielikuma pašreizējo faila nosaukumu.',
      name: 'Apkopotais pielikuma faila nosaukums'
    },
    customTokens: {
      description: 'Izmantojamie pielāgotie tokeni.\nSīkāku informāciju skatiet {{documentation}}.\n⚠️ Pielāgotie tokeni var būt patvaļīgs JavaScript kods. Ja tas ir slikti uzrakstīts, tas var izraisīt datu zudumu. Izmantojiet uz savu risku.',
      name: 'Pielāgotie tokeni'
    },
    defaultImageSize: {
      description: 'Noklusējuma attēla izmērs.\nVar norādīt pikseļos ({{pixels}}) vai procentos no pilnā attēla izmēra ({{percentage}}).\nAtstājiet tukšu, lai izmantotu oriģinālo attēla izmēru.',
      name: 'Noklusējuma attēla izmērs'
    },
    duplicateNameSeparator: {
      description: 'Kad ielīmējat vai velkat failu ar tādu pašu nosaukumu kā esošam failam, faila nosaukumam tiks pievienots šis atdalītājs.\nPiemēram, velkot failu {{existingFile}}, tas tiks pārdēvēts par {{firstAvailableName}}, {{secondAvailableName}} utt., izvēloties pirmo pieejamo nosaukumu.',
      name: 'Dublēto nosaukumu atdalītājs'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Izslēgt pielikumus no šādiem ceļiem, kad tiek izpildīta komanda {{command}}.\nIevadiet katru ceļu jaunā rindā.\n{{pathSyntax}}\nJa iestatījums ir tukšs, neviens ceļš netiek izslēgts no pielikumu apkopošanas.',
      name: 'Izslēgt ceļus no pielikumu apkopošanas'
    },
    generatedAttachmentFileName: {
      description: 'Skatiet pieejamos {{tokens}}.',
      name: 'Ģenerētais pielikuma faila nosaukums'
    },
    jpegQuality: {
      description: 'Jo mazāka kvalitāte, jo lielāks saspiešanas koeficients.',
      name: 'JPEG kvalitāte'
    },
    locationForNewAttachments: {
      description: 'Sāciet ar {{relativePrefix}}, lai norādītu ceļu attiecībā pret piezīmes vecākmapi.\nSkatiet pieejamos {{tokens}}.\nPunktu mapes, piemēram, {{dotFolder}}, nav ieteicamas, jo Obsidian tās neuzrauga. To pārvaldīšanai var būt nepieciešams spraudnis {{unhidePlugin}}.',
      name: 'Jauno pielikumu atrašanās vieta'
    },
    markdownUrlFormat: {
      description: 'URL formāts, kas tiks ievietots Markdown, kad tiek pievienots pielikums. Tas tiek piemērots tikai tajā brīdī: saitei, ko Obsidian vēlāk pārraksta, kad piezīme vai pielikums tiek pārdēvēts vai pārvietots, tiek piemērots noklusējuma formāts.\nSkatiet pieejamos {{tokens}}.\nAtstājiet tukšu, lai izmantotu noklusējuma formātu.',
      name: 'Markdown URL formāts'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Vai pielikumu mapes un faila nosaukuma iestatījumus piemērot pielikumiem, ko izveido CITI spraudņi.\nDaži spraudņi ieraksta pielikumu glabātavā ar savu nosaukumu, nejautājot Obsidian, kur tam būtu jāatrodas. Ja šis ir ieslēgts, šāds fails tiek pārvietots un pārdēvēts uzreiz pēc parādīšanās.\nTiek apstrādāti tikai faili, kas radīti, kamēr piezīme ir atvērta, un uz kuriem saitē kāda piezīme: fails, uz kuru nesaitē neviena piezīme, ir dati, ko cits spraudnis glabā sev, un tas paliek tur, kur tika ierakstīts. Faili, kas nāk no sinhronizācijas vai glabātavas importa, netiek apstrādāti nekad.\n{{modes}}\nSpraudnis, kas izveido failu, tiek noteikts pēc ieraksta izsaukumu steka. Tas notiek pēc labākās iespējas: spraudnis netiek noteikts failam, ko ierakstījis pats Obsidian, sinhronizācijas klients vai spraudnis, kas atliek savu ierakstu. Šāds fails tiek uzskatīts par TĀDU, KAS NAV zemāk esošajā sarakstā.',
      name: 'Pārdēvēt pielikumus, ko izveido citi spraudņi'
    },
    renameAttachmentsToLowerCase: 'Pārdēvēt pielikumus uz mazajiem burtiem',
    renamedAttachmentFileName: {
      description: 'Skatiet pieejamos {{tokens}}.\nAtstājiet tukšu, lai saglabātu pielikuma pašreizējo faila nosaukumu.',
      name: 'Pārdēvētais pielikuma faila nosaukums'
    },
    resetToSampleCustomTokens: {
      message: 'Vai tiešām vēlaties atiestatīt pielāgotos tokenus uz parauga pielāgotajiem tokeniem? Jūsu izmaiņas tiks zaudētas.',
      title: 'Atiestatīt uz parauga pielāgotajiem tokeniem'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Vai konvertēt ielīmētos attēlus uz JPEG. Attiecas tikai tad, kad PNG attēla saturs tiek ielīmēts tieši no starpliktuvnes. Parasti ekrānuzņēmumu ielīmēšanai.',
      name: 'Vai konvertēt ielīmētos attēlus uz JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Ja iespējots, pielikumi, kas apstrādāti ar komandām {{command}}, tiks pārdēvēti saskaņā ar iestatījumu {{setting}}.',
      name: 'Vai pārdēvēt apkopotos pielikumus'
    },
    specialCharacters: {
      description: 'Īpašās rakstzīmes pielikumu mapē un faila nosaukumā, kas jāaizstāj vai jānoņem.\nAtstājiet tukšu, lai saglabātu īpašās rakstzīmes.',
      name: 'Īpašās rakstzīmes'
    },
    specialCharactersReplacement: {
      description: 'Aizstāšanas virkne īpašajām rakstzīmēm pielikumu mapē un faila nosaukumā.\nAtstājiet tukšu, lai noņemtu īpašās rakstzīmes.',
      name: 'Īpašo rakstzīmju aizstāšana'
    },
    timeoutInSeconds: {
      description: 'Laika ierobežojums sekundēs visām operācijām.\nJa ir iestatīts {{zero}}, operāciju izpildes laika ierobežojums ir atspējots.',
      name: 'Laika ierobežojums sekundēs'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Pārdēvēt pielikuma failu',
    folderTitle: 'Izvēlieties pielikumu mapi',
    previewModal: {
      title: 'Pielikuma faila priekšskatījums \'{{fullFileName}}\''
    },
    title: 'Norādiet vērtību prompt tokenam'
  },
  regularExpression: '/regulārā izteiksme/'
};
