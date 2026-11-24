export const pl = {
  attachmentCollector: {
    confirm: 'Czy chcesz rekursywnie zebrać załączniki dla wszystkich notatek w folderach?\n{{folders}}\nTej operacji nie można cofnąć.',
    progressBar: {
      message: 'Zbieranie załączników {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Zbieranie załączników...'
    }
  },
  buttons: {
    copy: 'Kopiuj',
    move: 'Przenieś',
    previewAttachmentFile: 'Podgląd pliku załącznika',
    skip: 'Pomiń'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Załącznik {{attachment}} jest używany przez wiele notatek.',
    heading: 'Zbieranie załącznika używanego przez wiele notatek',
    noPriorityWinnerReason: {
      EmptyList: 'Nie został przeniesiony, ponieważ ustawienie {{settingName}} jest puste, więc nic nie rozstrzyga, do której z tych notatek należy.',
      NoMatch: 'Nie został przeniesiony, ponieważ żadna z tych notatek nie pasuje do jakiegokolwiek wpisu w ustawieniu {{settingName}}.',
      Tie: 'Nie został przeniesiony, ponieważ kilka z tych notatek pasuje do ustawienia {{settingName}} równie dobrze, więc nie wskazuje ono jednego właściciela.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Użyj tej samej akcji dla innych problematycznych załączników'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Zbierz załączniki w bieżącym folderze',
    collectAttachmentsCurrentNote: 'Zbierz załączniki w bieżącej notatce',
    collectAttachmentsEntireVault: 'Zbierz załączniki w całym sejfie'
  },
  links: {
    documentation: 'dokumentację',
    tokens: 'tokeny'
  },
  menuItems: {
    collectAttachmentsInFile: 'Zbierz załączniki w pliku',
    collectAttachmentsInFiles: 'Zbierz załączniki w plikach'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Zbieranie załączników dla \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Zbieranie załączników anulowane. Zobacz konsolę dla szczegółów.',
    generatedAttachmentFileNameIsInvalid: 'Wygenerowana nazwa pliku załącznika \'{{path}}\' jest nieprawidłowa.\n{{validationMessage}}\nSprawdź ustawienie {{settingName}}.',
    notePathIsIgnored: 'Ścieżka notatki jest ignorowana'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Anuluj',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Elementy na stronie:',
      jumpToPage: 'Przejdź do strony:'
    },
    notices: {
      attachmentIsStillUsed: 'Załącznik {{attachmentPath}} jest nadal używany przez inne notatki. Nie zostanie usunięty.',
      unhandledError: 'Wystąpił nieobsługiwany błąd. Sprawdź konsolę dla więcej informacji.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'wszystkie pliki są przemianowywane.',
        displayText: 'Wszystkie'
      },
      none: {
        description: 'ich nazwy są zachowane.',
        displayText: 'Żadne'
      },
      onlyPastedImages: {
        description: 'tylko wklejone obrazy są przemianowywane. Dotyczy tylko sytuacji, gdy zawartość obrazu PNG jest wklejana bezpośrednio ze schowka. Zazwyczaj do wklejania zrzutów ekranu.',
        displayText: 'Tylko wklejone obrazy'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'anuluj zbieranie załączników.',
        displayText: 'Anuluj'
      },
      copy: {
        description: 'skopiuj załącznik do nowej lokalizacji.',
        displayText: 'Kopiuj'
      },
      move: {
        description: 'przenieś załącznik do nowej lokalizacji.',
        displayText: 'Przenieś'
      },
      prompt: {
        description: 'zapytaj użytkownika o wybór akcji.',
        displayText: 'Zapytaj'
      },
      skip: {
        description: 'pomiń załącznik i przejdź do następnego.',
        displayText: 'Pomiń'
      }
    },
    defaultImageSizeDimension: {
      height: 'Wysokość',
      width: 'Szerokość'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Niestandardowe tokeny zostały zakomentowane, ponieważ muszą zostać zaktualizowane do nowego formatu wprowadzonego w wersji wtyczki 9.0.0.\n// Zapoznaj się z dokumentacją ({{customTokensDocumentationUrl}}), aby uzyskać więcej informacji.',
      deprecated: 'Zmienił się format rejestracji niestandardowych tokenów. Zaktualizuj odpowiednio swoje tokeny. Zobacz {{documentation}}, aby uzyskać więcej informacji.'
    },
    legacyRenameAttachmentsToLowerCase: 'Ustawienie {{setting}} jest przestarzałe. Zamiast niego użyj formatu {{format}}. Zobacz {{documentation}}, aby uzyskać więcej informacji.',
    markdownUrlFormat: {
      deprecated: 'Dla formatu {{setting}} może być ustawiona niepoprawna wartość. Zobacz {{documentation}}, aby uzyskać więcej informacji. Ta wiadomość nie zostanie ponownie wyświetlona.'
    },
    specialCharacters: 'Domyślna wartość ustawienia {{setting}} została zmieniona. Twoje ustawienie zostało zaktualizowane do nowej wartości domyślnej.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Domyślny rozmiar obrazu musi być w pikselach lub procentach',
      invalidCustomTokensCode: 'Nieprawidłowy kod niestandardowych tokenów',
      invalidRegularExpression: 'Nieprawidłowe wyrażenie regularne {{regExp}}',
      specialCharactersMustNotContainSlash: 'Znaki specjalne nie mogą zawierać /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Zamiana znaków specjalnych nie może zawierać nieprawidłowych znaków ścieżki nazwy pliku.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Podczas dołączania plików:',
      name: 'Tryb przemianowania załączników'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Gdy zebrany załącznik jest używany przez wiele notatek:',
      name: 'Tryb zbierania załączników używanych przez wiele notatek'
    },
    collectedAttachmentFileName: {
      description: 'Zobacz dostępne {{tokens}}.\nPozostaw puste, aby zachować bieżącą nazwę pliku załącznika.',
      name: 'Zebrana nazwa pliku załącznika'
    },
    customTokens: {
      description: 'Niestandardowe tokeny do użycia.\nZobacz {{documentation}}, aby uzyskać więcej informacji.\n⚠️ Niestandardowe tokeny mogą być dowolnym kodem JavaScript. Jeśli są napisane nieprawidłowo, mogą spowodować utratę danych. Używasz ich na własne ryzyko.',
      name: 'Niestandardowe tokeny'
    },
    defaultImageSize: {
      description: 'Domyślny rozmiar obrazu.\nMożna go określić w pikselach ({{pixels}}) lub jako procent pełnego rozmiaru obrazu ({{percentage}}).\nPozostaw puste, aby użyć oryginalnego rozmiaru obrazu.',
      name: 'Domyślny rozmiar obrazu'
    },
    duplicateNameSeparator: {
      description: 'Gdy wklejasz lub przeciągasz plik o tej samej nazwie co istniejący plik, do nazwy pliku zostanie dodany ten separator.\nNp. gdy przeciągasz plik {{existingFile}}, zostanie on przemianowany na {{firstAvailableName}}, {{secondAvailableName}} itd. — wybierana jest pierwsza dostępna nazwa.',
      name: 'Separator duplikowanych nazw'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Wyklucz załączniki z następujących ścieżek, gdy wykonywane jest polecenie {{command}}.\nWstaw każdą ścieżkę w nowej linii.\n{{pathSyntax}}\nJeśli ustawienie jest puste, żadne ścieżki nie są wykluczane ze zbierania załączników.',
      name: 'Wyklucz ścieżki ze zbierania załączników'
    },
    generatedAttachmentFileName: {
      description: 'Zobacz dostępne {{tokens}}.',
      name: 'Wygenerowana nazwa pliku załącznika'
    },
    jpegQuality: {
      description: 'Im mniejsza jakość, tym większy współczynnik kompresji.',
      name: 'Jakość JPEG'
    },
    locationForNewAttachments: {
      description: 'Zacznij od {{relativePrefix}}, aby podać ścieżkę względem folderu nadrzędnego notatki.\nZobacz dostępne {{tokens}}.\nFoldery kropkowe, takie jak {{dotFolder}}, nie są zalecane, ponieważ Obsidian ich nie śledzi. Do zarządzania nimi może być potrzebna wtyczka {{unhidePlugin}}.',
      name: 'Lokalizacja nowych załączników'
    },
    markdownUrlFormat: {
      description: 'Format adresu URL wstawianego do Markdown podczas dodawania załącznika. Jest stosowany tylko w tym momencie: link, który Obsidian przepisze później, przy zmianie nazwy lub przeniesieniu notatki albo załącznika, otrzyma format domyślny.\nZobacz dostępne {{tokens}}.\nPozostaw puste, aby użyć domyślnego formatu.',
      name: 'Format adresu URL w Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Czy stosować ustawienia folderu załączników i nazwy pliku do załączników tworzonych przez INNE wtyczki.\nNiektóre wtyczki zapisują załącznik do skarbca pod własną nazwą, nie pytając Obsidiana, gdzie powinien trafić. Gdy ta opcja jest włączona, taki plik zostaje przeniesiony i przemianowany zaraz po pojawieniu się.\nDotyczy to tylko plików utworzonych przy otwartej notatce i podlinkowanych w notatce: plik, do którego nie prowadzi link z żadnej notatki, to dane, które inna wtyczka przechowuje na własny użytek, więc pozostaje tam, gdzie został zapisany. Pliki pochodzące z synchronizacji lub importu skarbca nigdy nie są zmieniane.\n{{modes}}\nWtyczka, która utworzyła plik, jest rozpoznawana na podstawie stosu wywołań zapisu. Działa to w miarę możliwości: żadna wtyczka nie zostanie rozpoznana dla pliku zapisanego przez sam Obsidian, przez klienta synchronizacji ani przez wtyczkę, która odracza zapis. Taki plik uznaje się za NIEOBECNY na poniższej liście.',
      name: 'Zmieniaj nazwy załączników tworzonych przez inne wtyczki'
    },
    renameAttachmentsToLowerCase: 'Przemianuj załączniki na małe litery',
    renamedAttachmentFileName: {
      description: 'Zobacz dostępne {{tokens}}.\nPozostaw puste, aby zachować bieżącą nazwę pliku załącznika.',
      name: 'Przemianowana nazwa pliku załącznika'
    },
    resetToSampleCustomTokens: {
      message: 'Czy na pewno chcesz zresetować niestandardowe tokeny do przykładowych? Twoje zmiany zostaną utracone.',
      title: 'Resetuj do przykładowych niestandardowych tokenów'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Czy konwertować wklejone obrazy do JPEG. Dotyczy tylko sytuacji, gdy zawartość obrazu PNG jest wklejana bezpośrednio ze schowka (zazwyczaj przy wklejaniu zrzutów ekranu).',
      name: 'Czy konwertować wklejone obrazy do JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Jeśli włączone, załączniki przetworzone przez polecenia {{command}} zostaną przemianowane zgodnie z ustawieniem {{setting}}.',
      name: 'Czy przemianować zebrane załączniki'
    },
    specialCharacters: {
      description: 'Znaki specjalne w nazwie folderu i pliku załącznika do zastąpienia lub usunięcia.\nPozostaw puste, aby zachować znaki specjalne.',
      name: 'Znaki specjalne'
    },
    specialCharactersReplacement: {
      description: 'Ciąg zastępujący znaki specjalne w nazwie folderu i pliku załącznika.\nPozostaw puste, aby usuwać znaki specjalne.',
      name: 'Zamiana znaków specjalnych'
    },
    timeoutInSeconds: {
      description: 'Limit czasu (w sekundach) dla wszystkich operacji.\nJeśli ustawisz {{zero}}, limit czasu wykonywania operacji zostanie wyłączony.',
      name: 'Limit czasu w sekundach'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Zmień nazwę pliku załącznika',
    folderTitle: 'Wybierz folder załączników',
    previewModal: {
      title: 'Podgląd pliku załącznika \'{{fullFileName}}\''
    },
    title: 'Podaj wartość dla tokena promptu'
  },
  regularExpression: '/wyrażenie regularne/'
};
