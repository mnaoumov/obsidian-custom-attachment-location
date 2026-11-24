export const ro = {
  attachmentCollector: {
    confirm: 'Doriți să colectați recursiv atașamentele pentru toate notițele din foldere?\n{{folders}}\nAceastă operațiune nu poate fi anulată.',
    progressBar: {
      message: 'Colectez atașamente {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Colectez atașamente...'
    }
  },
  buttons: {
    copy: 'Copiază',
    move: 'Mută',
    previewAttachmentFile: 'Previzualizează fișierul atașat',
    skip: 'Sari peste'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Atașamentul {{attachment}} este folosit de mai multe notițe.',
    heading: 'Colectez atașamentul folosit de multiple notițe',
    noPriorityWinnerReason: {
      EmptyList: 'Nu a fost mutat deoarece setarea {{settingName}} este goală, așa că nimic nu stabilește căreia dintre aceste note îi aparține.',
      NoMatch: 'Nu a fost mutat deoarece niciuna dintre aceste note nu corespunde vreunei intrări din setarea {{settingName}}.',
      Tie: 'Nu a fost mutat deoarece mai multe dintre aceste note corespund la fel de bine setării {{settingName}}, astfel încât aceasta nu desemnează un singur proprietar.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Folosește aceeași acțiune pentru alte atașamente problematice'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Colectează atașamentele din dosarul curent',
    collectAttachmentsCurrentNote: 'Colectează atașamentele din notița curentă',
    collectAttachmentsEntireVault: 'Colectează atașamentele din întregul seif'
  },
  links: {
    documentation: 'documentația',
    tokens: 'tokenurile'
  },
  menuItems: {
    collectAttachmentsInFile: 'Colectează atașamentele în fișier',
    collectAttachmentsInFiles: 'Colectează atașamentele în fișiere'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Colectez atașamentele pentru \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Colectarea atașamentelor a fost anulată. Verifică consola pentru detalii.',
    generatedAttachmentFileNameIsInvalid: 'Numele generat al fișierului atașat \'{{path}}\' este invalid.\n{{validationMessage}}\nVerifică setarea {{settingName}}.',
    notePathIsIgnored: 'Calea notiței a fost ignorată'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Anulează',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Elemente pe pagină:',
      jumpToPage: 'Sari la pagina:'
    },
    notices: {
      attachmentIsStillUsed: 'Atașamentul {{attachmentPath}} este încă folosit de alte notițe. Nu va fi șters.',
      unhandledError: 'A apărut o eroare neprevăzută. Verifică consola pentru mai multe informații.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'toate fișierele sunt redenumite.',
        displayText: 'Toate'
      },
      none: {
        description: 'numele lor sunt păstrate.',
        displayText: 'Niciunul'
      },
      onlyPastedImages: {
        description: 'doar imaginile lipite sunt redenumite. Se aplică doar când conținutul imaginii PNG este lipit direct din clipboard. De obicei, pentru capturi de ecran.',
        displayText: 'Doar imaginile lipite'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'anulează colectarea atașamentelor.',
        displayText: 'Anulează'
      },
      copy: {
        description: 'copiază atașamentul în noua locație.',
        displayText: 'Copiază'
      },
      move: {
        description: 'mută atașamentul în noua locație.',
        displayText: 'Mută'
      },
      prompt: {
        description: 'cere utilizatorului să aleagă acțiunea.',
        displayText: 'Solicită'
      },
      skip: {
        description: 'sari peste atașament și continuă cu următorul.',
        displayText: 'Sari peste'
      }
    },
    defaultImageSizeDimension: {
      height: 'Înălțime',
      width: 'Lățime'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Tokenurile personalizate au fost comentate deoarece trebuie actualizate la noul format introdus în versiunea 9.0.0 a pluginului.\n// Consultă documentația ({{customTokensDocumentationUrl}}) pentru mai multe informații.',
      deprecated: 'Formatul de înregistrare a tokenurilor personalizate s-a schimbat. Actualizează tokenurile corespunzător. Consultă {{documentation}} pentru mai multe informații.'
    },
    legacyRenameAttachmentsToLowerCase: 'Setarea {{setting}} este depreciată. Folosește în schimb formatul {{format}}. Consultă {{documentation}} pentru mai multe informații.',
    markdownUrlFormat: {
      deprecated: 'Aveți o valoare potențial incorectă setată pentru formatul {{setting}}. Consultați {{documentation}} pentru mai multe informații. Acest mesaj nu va mai fi afișat.'
    },
    specialCharacters: 'Valoarea implicită a setării {{setting}} a fost schimbată. Valoarea voastră a fost actualizată la noua valoare implicită.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Dimensiunea implicită a imaginii trebuie să fie în pixeli sau procente',
      invalidCustomTokensCode: 'Cod de token personalizat invalid',
      invalidRegularExpression: 'Expresie regulată invalidă {{regExp}}',
      specialCharactersMustNotContainSlash: 'Caracterele speciale nu trebuie să conțină /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Înlocuirea caracterelor speciale nu trebuie să conțină caractere invalide de cale de fișier.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Când atașați fișiere:',
      name: 'Mod de redenumire atașamente'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Când atașamentul colectat este folosit de mai multe notițe:',
      name: 'Mod colectare atașamente folosite de mai multe notițe'
    },
    collectedAttachmentFileName: {
      description: 'Vezi {{tokens}} disponibile.\nLăsați gol pentru a păstra numele curent al fișierului atașat.',
      name: 'Nume fișier atașament colectat'
    },
    customTokens: {
      description: 'Tokenuri personalizate de utilizat.\nConsultă {{documentation}} pentru mai multe informații.\n⚠️ Tokenurile personalizate pot conține cod JavaScript arbitrar. Dacă sunt scrise greșit, pot cauza pierderi de date. Folosiți-le pe propria răspundere.',
      name: 'Tokenuri personalizate'
    },
    defaultImageSize: {
      description: 'Dimensiunea implicită a imaginii.\nPoate fi specificată în pixeli ({{pixels}}) sau ca procent din dimensiunea totală a imaginii ({{percentage}}).\nLăsați gol pentru a folosi dimensiunea originală a imaginii.',
      name: 'Dimensiune implicită imagine'
    },
    duplicateNameSeparator: {
      description: 'Când lipiți/trageți un fișier cu același nume ca un fișier existent, acest separator va fi adăugat la numele fișierului.\nDe exemplu, când trageți fișierul {{existingFile}}, acesta va fi redenumit în {{firstAvailableName}}, {{secondAvailableName}} etc., folosind primul nume disponibil.',
      name: 'Separator pentru nume duplicate'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Excludeți atașamentele din următoarele căi când se execută comanda {{command}}.\nIntroduceți fiecare cale pe o linie nouă.\n{{pathSyntax}}\nDacă setarea este goală, nu se exclude nicio cale din colectarea atașamentelor.',
      name: 'Excludere căi pentru colectarea atașamentelor'
    },
    generatedAttachmentFileName: {
      description: 'Vezi {{tokens}} disponibile.',
      name: 'Nume fișier atașament generat'
    },
    jpegQuality: {
      description: 'Cu cât calitatea este mai mică, cu atât rata de compresie este mai mare.',
      name: 'Calitate JPEG'
    },
    locationForNewAttachments: {
      description: 'Începeți cu {{relativePrefix}} pentru căi relative la dosarul părinte al notiței.\nVezi {{tokens}} disponibile.\nDosarele cu punct, precum {{dotFolder}}, nu sunt recomandate, deoarece Obsidian nu le urmărește. Este posibil să aveți nevoie de pluginul {{unhidePlugin}} pentru a le gestiona.',
      name: 'Locația pentru atașamente noi'
    },
    markdownUrlFormat: {
      description: 'Formatul URL-ului care va fi inserat în Markdown când se adaugă un atașament. Se aplică doar în acel moment: un link pe care Obsidian îl rescrie mai târziu, când o notiță sau un atașament este redenumit sau mutat, primește formatul implicit.\nVezi {{tokens}} disponibile.\nLăsați necompletat pentru a folosi formatul implicit.',
      name: 'Format URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description:
        'Dacă setările pentru folderul de atașamente și numele fișierului se aplică și atașamentelor create de ALTE pluginuri.\nUnele pluginuri scriu un atașament direct în seif sub un nume propriu, fără să întrebe Obsidian unde ar trebui să ajungă. Cu această opțiune activată, un astfel de fișier este mutat și redenumit imediat ce apare.\nSunt afectate doar fișierele create cât timp o notiță este deschisă și spre care trimite un link dintr-o notiță: un fișier spre care nu trimite nicio notiță conține date pe care alt plugin le păstrează pentru sine și rămâne acolo unde a fost scris. Fișierele venite dintr-o sincronizare sau dintr-un import de seif nu sunt afectate niciodată.\n{{modes}}\nPluginul care a creat fișierul este identificat din stiva de apeluri a scrierii. Identificarea se face în măsura posibilului: niciun plugin nu este identificat pentru un fișier scris de Obsidian însuși, de un client de sincronizare sau de un plugin care își amână scrierea. Un astfel de fișier este considerat ca NEFIIND în lista de mai jos.',
      name: 'Redenumește atașamentele create de alte pluginuri'
    },
    renameAttachmentsToLowerCase: 'Redenumește atașamentele cu litere mici',
    renamedAttachmentFileName: {
      description: 'Vezi {{tokens}} disponibile.\nLăsați gol pentru a păstra numele curent al fișierului atașat.',
      name: 'Nume fișier atașament redenumit'
    },
    resetToSampleCustomTokens: {
      message: 'Sigur doriți să resetați tokenurile personalizate la tokenurile exemplu? Modificările dvs. vor fi pierdute.',
      title: 'Resetează la tokenuri exemplu'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Stabilește dacă imaginile lipite să fie convertite în JPEG. Se aplică numai când conținutul unei imagini PNG este lipit direct din clipboard. De obicei, pentru capturi de ecran.',
      name: 'Convertiți imaginile lipite în JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Dacă este activat, atașamentele procesate prin comenzile {{command}} vor fi redenumite conform setării {{setting}}.',
      name: 'Redenumește atașamentele colectate'
    },
    specialCharacters: {
      description: 'Caractere speciale în numele dosarului și fișierului atașament care vor fi înlocuite sau eliminate.\nLăsați gol pentru a păstra caracterele speciale.',
      name: 'Caractere speciale'
    },
    specialCharactersReplacement: {
      description: 'Șir de înlocuire pentru caracterele speciale din numele dosarului și fișierului atașament.\nLăsați gol pentru a elimina caracterele speciale.',
      name: 'Înlocuire caractere speciale'
    },
    timeoutInSeconds: {
      description: 'Timpul limită în secunde pentru toate operațiile.\nDacă este setat {{zero}}, timpul limită pentru executarea operațiilor este dezactivat.',
      name: 'Timp limită (secunde)'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Redenumește fișierul atașat',
    folderTitle: 'Alege folderul de atașamente',
    previewModal: {
      title: 'Previzualizează fișierul atașat \'{{fullFileName}}\''
    },
    title: 'Furnizați o valoare pentru tokenul de prompt'
  },
  regularExpression: '/expresie regulată/'
};
