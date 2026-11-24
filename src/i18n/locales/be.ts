export const be = {
  attachmentCollector: {
    confirm: 'Сабраць далучэнні для ўсіх нататак у папках рэкурсіўна?\n{{folders}}\nГэтую аперацыю нельга адмяніць.',
    progressBar: {
      message: 'Збор далучэнняў {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Збор далучэнняў...'
    }
  },
  buttons: {
    copy: 'Капіяваць',
    move: 'Перамясціць',
    previewAttachmentFile: 'Праглядзець файл далучэння',
    skip: 'Прапусціць'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Далучэнне {{attachment}} выкарыстоўваецца некалькімі нататкамі.',
    heading: 'Збор далучэння, якое выкарыстоўваецца некалькімі нататкамі',
    noPriorityWinnerReason: {
      EmptyList: 'Ён не быў перамешчаны, бо налада {{settingName}} пустая, таму нішто не вызначае, якой з гэтых нататак ён належыць.',
      NoMatch: 'Ён не быў перамешчаны, бо ніводная з гэтых нататак не адпавядае ніводнаму запісу ў наладзе {{settingName}}.',
      Tie: 'Ён не быў перамешчаны, бо некалькі з гэтых нататак аднолькава адпавядаюць наладзе {{settingName}}, таму яна не называе адзінага ўладальніка.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Ці выкарыстоўваць тое ж дзеянне для іншых праблемных далучэнняў'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Сабраць далучэнні ў бягучай папцы',
    collectAttachmentsCurrentNote: 'Сабраць далучэнні ў бягучай нататцы',
    collectAttachmentsEntireVault: 'Сабраць далучэнні ва ўсёй сховішчы'
  },
  links: {
    documentation: 'дакументацыю',
    tokens: 'токены'
  },
  menuItems: {
    collectAttachmentsInFile: 'Сабраць укладанні ў файле',
    collectAttachmentsInFiles: 'Сабраць укладанні ў файлах'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Збор далучэнняў для \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Збор далучэнняў адменены. Глядзіце кансоль для падрабязнасцей.',
    generatedAttachmentFileNameIsInvalid: 'Згенераванае імя файла далучэння \'{{path}}\' недапушчальнае.\n{{validationMessage}}\nПраверце параметр {{settingName}}.',
    notePathIsIgnored: 'Шлях нататкі ігнаруецца'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Адмена',
      ok: 'ОК'
    },
    dataview: {
      itemsPerPage: 'Элементаў на старонцы:',
      jumpToPage: 'Перайсці на старонку:'
    },
    notices: {
      attachmentIsStillUsed: 'Далучэнне {{attachmentPath}} усё яшчэ выкарыстоўваецца іншымі нататкамі. Яно не будзе выдалена.',
      unhandledError: 'Адбылася неапрацаваная памылка. Калі ласка, праверце кансоль для атрымання дадатковай інфармацыі.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'усе файлы перайменаваны.',
        displayText: 'Усе'
      },
      none: {
        description: 'іх назвы захаваны.',
        displayText: 'Ніводны'
      },
      onlyPastedImages: {
        description: 'перайменаваны толькі ўстаўленыя выявы. Ужываецца толькі калі змесціва PNG выявы ўстаўляецца непасрэдна з буфера абмену. Звычайна для ўстаўкі скрыншотаў.',
        displayText: 'Толькі ўстаўленыя выявы'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'адмяніць збор далучэнняў.',
        displayText: 'Адмена'
      },
      copy: {
        description: 'скапіяваць далучэнне ў новую месцазнаходжанне.',
        displayText: 'Капіяваць'
      },
      move: {
        description: 'перамясціць далучэнне ў новую месцазнаходжанне.',
        displayText: 'Перамясціць'
      },
      prompt: {
        description: 'запытаць карыстальніка выбраць дзеянне.',
        displayText: 'Запыт'
      },
      skip: {
        description: 'прапусціць далучэнне і перайсці да наступнага.',
        displayText: 'Прапусціць'
      }
    },
    defaultImageSizeDimension: {
      height: 'Вышыня',
      width: 'Шырыня'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Карыстальніцкія токены былі закаментаваны, паколькі яны павінны быць абноўлены да новага фармату, уведзенага ў версіі плагіна 9.0.0.\n// Звярніцеся да дакументацыі ({{customTokensDocumentationUrl}}) для атрымання дадатковай інфармацыі.',
      deprecated: 'Фармат рэгістрацыі карыстальніцкіх токенаў змяніўся. Калі ласка, абнавіце вашы токены адпаведна. Падрабязней глядзіце {{documentation}}.'
    },
    legacyRenameAttachmentsToLowerCase: 'Параметр {{setting}} састарэлы. Выкарыстоўвайце замест яго фармат {{format}}. Падрабязней глядзіце {{documentation}}.',
    markdownUrlFormat: {
      deprecated: 'Магчыма, для фармату {{setting}} у вас зададзена няправільнае значэнне. Падрабязней глядзіце {{documentation}}. Гэта паведамленне больш не будзе паказана.'
    },
    specialCharacters: 'Значэнне параметра {{setting}} па змаўчанні было зменена. Ваша значэнне параметра было абноўлена да новага значэння па змаўчанні.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Прадвызначаны памер выявы павінен быць у пікселях або ў працэнтах',
      invalidCustomTokensCode: 'Няправільны код карыстальніцкіх токенаў',
      invalidRegularExpression: 'Няправільны рэгулярны выраз {{regExp}}',
      specialCharactersMustNotContainSlash: 'Спецыяльныя сімвалы не павінны змяшчаць /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Замена спецыяльных сімвалаў не павінна змяшчаць няправільныя сімвалы шляху імя файла.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Пры далучэнні файлаў:',
      name: 'Рэжым перайменавання далучэнняў'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Калі сабранае далучэнне выкарыстоўваецца некалькімі нататкамі:',
      name: 'Рэжым збору далучэння, якое выкарыстоўваецца некалькімі нататкамі'
    },
    collectedAttachmentFileName: {
      description: 'Глядзіце даступныя {{tokens}}.\nПакіньце пустым, каб захаваць бягучае імя файла далучэння.',
      name: 'Імя файла сабранага далучэння'
    },
    customTokens: {
      description: 'Карыстальніцкія токены для выкарыстання.\nПадрабязней глядзіце {{documentation}}.\n⚠️ Карыстальніцкія токены могуць быць адвольным JavaScript кодам. Калі яны дрэнна напісаны, гэта можа прывесці да страты даных. Выкарыстоўвайце на свой рызыку.',
      name: 'Карыстальніцкія токены'
    },
    defaultImageSize: {
      description: 'Прадвызначаны памер выявы.\nМожа быць указаны ў пікселях ({{pixels}}) або ў працэнтах ад поўнага памеру выявы ({{percentage}}).\nПакіньце пустым, каб выкарыстоўваць арыгінальны памер выявы.',
      name: 'Прадвызначаны памер выявы'
    },
    duplicateNameSeparator: {
      description: 'Калі вы ўстаўляеце/перацягваеце файл з тым жа імем, што і існуючы файл, гэты раздзяляльнік будзе дададзены да імя файла.\nНапрыклад, калі вы перацягваеце файл {{existingFile}}, ён будзе перайменаваны ў {{firstAvailableName}}, {{secondAvailableName}} і г.д., атрымліваючы першае даступнае імя.',
      name: 'Раздзяляльнік дублікатаў імёнаў'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Выключаць далучэнні з наступных шляхоў пры выкананні каманды {{command}}.\nУстаўце кожны шлях на новы радок.\n{{pathSyntax}}\nКалі параметр пусты, ніякія шляхі не выключаюцца са збору далучэнняў.',
      name: 'Выключыць шляхі з збору далучэнняў'
    },
    generatedAttachmentFileName: {
      description: 'Глядзіце даступныя {{tokens}}.',
      name: 'Згенераванае імя файла далучэння'
    },
    jpegQuality: {
      description: 'Чым менш якасць, тым больш каэфіцыент сціску.',
      name: 'Якасць JPEG'
    },
    locationForNewAttachments: {
      description: 'Пачніце з {{relativePrefix}} для шляхоў адносна бацькоўскай папкі нататкі.\nГлядзіце даступныя {{tokens}}.\nКропкавыя папкі, такія як {{dotFolder}}, не рэкамендуюцца, паколькі Obsidian не адсочвае іх. Каб кіраваць імі, вам можа спатрэбіцца плагін {{unhidePlugin}}.',
      name: 'Месцазнаходжанне для новых далучэнняў'
    },
    markdownUrlFormat: {
      description: 'Фармат URL, які будзе ўстаўлены ў Markdown пры даданні далучэння. Ён ужываецца толькі ў гэты момант: спасылка, якую Obsidian перапісвае пазней, калі нататка ці далучэнне перайменоўваецца або перамяшчаецца, атрымлівае фармат па змаўчанні.\nГлядзіце даступныя {{tokens}}.\nПакіньце пустым для выкарыстання фармату па змаўчанні.',
      name: 'Фармат URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Ці ўжываць налады папкі далучэнняў і імя файла да далучэнняў, якія ствараюць ІНШЫЯ плагіны.\nНекаторыя плагіны запісваюць далучэнне ў сховішча пад уласным імем, не пытаючыся ў Obsidian, дзе яму месца. Калі гэта ўключана, такі файл перамяшчаецца і перайменоўваецца адразу пасля з\'яўлення.\nЗакранаюцца толькі файлы, створаныя пры адкрытай нататцы, на якія спасылаецца нататка: файл, на які не спасылаецца ніводная нататка, — гэта даныя, якія іншы плагін захоўвае для сябе, і ён застаецца там, дзе быў запісаны. Файлы, якія прыходзяць з сінхранізацыі ці імпарту сховішча, ніколі не закранаюцца.\n{{modes}}\nПлагін-стваральнік вызначаецца па стэку выклікаў запісу. Гэта робіцца па магчымасці: для файла, запісанага самім Obsidian, кліентам сінхранізацыі або плагінам, які адкладвае запіс, плагін не вызначаецца. Такі файл лічыцца НЕ ўключаным у спіс ніжэй.',
      name: 'Перайменоўваць далучэнні, створаныя іншымі плагінамі'
    },
    renameAttachmentsToLowerCase: 'Перайменаваць далучэнні ў ніжні рэгістр',
    renamedAttachmentFileName: {
      description: 'Глядзіце даступныя {{tokens}}.\nПакіньце пустым, каб захаваць бягучае імя файла далучэння.',
      name: 'Імя перайменаванага файла далучэння'
    },
    resetToSampleCustomTokens: {
      message: 'Вы ўпэўнены, што хочаце скінуць карыстальніцкія токены да ўзорных карыстальніцкіх токенаў? Вашы змены будуць страчаны.',
      title: 'Скінуць да ўзорных карыстальніцкіх токенаў'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Ці канвертаваць устаўленыя выявы ў JPEG. Ужываецца толькі калі змесціва PNG выявы ўстаўляецца непасрэдна з буфера абмену. Звычайна для ўстаўкі скрыншотаў.',
      name: 'Ці канвертаваць устаўленыя выявы ў JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Калі ўключана, далучэнні, апрацаваныя камандамі {{command}}, будуць перайменаваны згодна з параметрам {{setting}}.',
      name: 'Ці перайменаваць сабраныя далучэнні'
    },
    specialCharacters: {
      description: 'Спецыяльныя сімвалы ў назве папкі далучэнняў і імені файла, якія трэба замяніць або выдаліць.\nПакіньце пустым для захавання спецыяльных сімвалаў.',
      name: 'Спецыяльныя сімвалы'
    },
    specialCharactersReplacement: {
      description: 'Радок замены для спецыяльных сімвалаў у назве папкі далучэнняў і імені файла.\nПакіньце пустым для выдалення спецыяльных сімвалаў.',
      name: 'Замена спецыяльных сімвалаў'
    },
    timeoutInSeconds: {
      description: 'Тайм-аўт у секундах для ўсіх аперацый.\nКалі ўстаноўлена {{zero}}, тайм-аўт выканання аперацый адключаецца.',
      name: 'Тайм-аўт у секундах'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Перайменаваць файл далучэння',
    folderTitle: 'Выберыце папку далучэнняў',
    previewModal: {
      title: 'Праглядзець файл далучэння \'{{fullFileName}}\''
    },
    title: 'Укажыце значэнне для токена запыту'
  },
  regularExpression: '/рэгулярны выраз/'
};
