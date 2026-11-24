export const ko = {
  attachmentCollector: {
    confirm: '다음 폴더에 있는 모든 노트의 첨부 파일을 재귀적으로 수집하시겠습니까?\n{{folders}}\n이 작업은 되돌릴 수 없습니다.',
    progressBar: {
      message: '첨부 파일 수집 중 {{iterationString}} - \'{{noteFilePath}}\'.',
      title: '첨부 파일 수집 중...'
    }
  },
  buttons: {
    copy: '복사',
    move: '이동',
    previewAttachmentFile: '첨부 파일 미리보기',
    skip: '건너뛰기'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: '첨부 파일 {{attachment}}이(가) 여러 노트에서 참조되고 있습니다.',
    heading: '여러 노트에서 사용되는 첨부 파일 수집',
    noPriorityWinnerReason: {
      EmptyList: '{{settingName}} 설정이 비어 있어 이 노트 중 어느 것이 소유하는지 결정할 수 없으므로 이동되지 않았습니다.',
      NoMatch: '이 노트 중 어느 것도 {{settingName}} 설정의 항목과 일치하지 않으므로 이동되지 않았습니다.',
      Tie: '이 노트 중 여러 개가 {{settingName}} 설정과 똑같이 일치하여 단일 소유자를 정할 수 없으므로 이동되지 않았습니다.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: '다른 문제가 있는 첨부 파일에 대해서도 같은 동작을 사용해야 합니다'
  },
  commands: {
    collectAttachmentsCurrentFolder: '현재 폴더의 첨부 파일 수집',
    collectAttachmentsCurrentNote: '현재 노트의 첨부 파일 수집',
    collectAttachmentsEntireVault: '전체 볼트의 첨부 파일 수집'
  },
  links: {
    documentation: '문서',
    tokens: '토큰'
  },
  menuItems: {
    collectAttachmentsInFile: '파일에서 첨부 파일 수집',
    collectAttachmentsInFiles: '여러 파일에서 첨부 파일 수집'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: '\'{{noteFilePath}}\'의 첨부 파일 수집 중',
    collectingAttachmentsCancelled: '첨부 파일 수집이 취소되었습니다. 자세한 내용은 콘솔을 확인하세요.',
    generatedAttachmentFileNameIsInvalid: '생성된 첨부 파일 이름 \'{{path}}\'이(가) 유효하지 않습니다.\n{{validationMessage}}\n{{settingName}} 설정을 확인하세요.',
    notePathIsIgnored: '노트 경로가 무시됩니다'
  },
  obsidianLib: {
    buttons: {
      cancel: '취소',
      ok: '확인'
    },
    dataview: {
      itemsPerPage: '페이지당 항목 수:',
      jumpToPage: '페이지로 이동:'
    },
    notices: {
      attachmentIsStillUsed: '첨부 파일 {{attachmentPath}}이(가) 다른 노트에서 여전히 사용되고 있습니다. 삭제되지 않습니다.',
      unhandledError: '처리되지 않은 오류가 발생했습니다. 자세한 내용은 콘솔을 확인하세요.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: '모든 파일의 이름이 변경됩니다.',
        displayText: '모두'
      },
      none: {
        description: '이름이 보존됩니다.',
        displayText: '없음'
      },
      onlyPastedImages: {
        description: '붙여넣은 이미지만 이름이 변경됩니다. PNG 이미지 내용이 클립보드에서 직접 붙여넣어질 때만 적용됩니다. 일반적으로 스크린샷 붙여넣기에 사용됩니다.',
        displayText: '붙여넣은 이미지만'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: '첨부 파일 수집을 취소합니다.',
        displayText: '취소'
      },
      copy: {
        description: '첨부 파일을 새 위치에 복사합니다.',
        displayText: '복사'
      },
      move: {
        description: '첨부 파일을 새 위치로 이동합니다.',
        displayText: '이동'
      },
      prompt: {
        description: '사용자에게 동작을 선택하도록 요청합니다.',
        displayText: '요청'
      },
      skip: {
        description: '첨부 파일을 건너뛰고 다음으로 진행합니다.',
        displayText: '건너뛰기'
      }
    },
    defaultImageSizeDimension: {
      height: '높이',
      width: '너비'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// 사용자 정의 토큰은 플러그인 버전 9.0.0에서 도입된 새 형식으로 업데이트해야 하므로 주석 처리되었습니다.\n// 자세한 내용은 문서({{customTokensDocumentationUrl}})를 참조하세요.',
      deprecated: '사용자 정의 토큰 등록 형식이 변경되었습니다. 토큰을 그에 맞게 업데이트하세요. 자세한 내용은 {{documentation}}를 참조하세요.'
    },
    legacyRenameAttachmentsToLowerCase: '{{setting}} 설정은 더 이상 사용되지 않습니다. 대신 {{format}} 형식을 사용하세요. 자세한 내용은 {{documentation}}를 참조하세요.',
    markdownUrlFormat: {
      deprecated: '{{setting}} 형식에 잘못된 값이 설정되어 있을 수 있습니다. 자세한 내용은 {{documentation}}를 참조하세요. 이 메시지는 다시 표시되지 않습니다.'
    },
    specialCharacters: '{{setting}} 설정의 기본값이 변경되었습니다. 설정 값이 새로운 기본값으로 업데이트되었습니다.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: '기본 이미지 크기는 픽셀 또는 백분율이어야 합니다',
      invalidCustomTokensCode: '유효하지 않은 사용자 정의 토큰 코드',
      invalidRegularExpression: '유효하지 않은 정규식 {{regExp}}',
      specialCharactersMustNotContainSlash: '특수 문자에는 /가 포함되어서는 안 됩니다',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: '특수 문자 대체에는 유효하지 않은 파일 이름 경로 문자가 포함되어서는 안 됩니다.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: '파일을 첨부할 때:',
      name: '첨부 파일 이름 변경 모드'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: '수집된 첨부 파일이 여러 노트에서 사용될 때:',
      name: '여러 노트에서 사용되는 첨부 파일 수집 모드'
    },
    collectedAttachmentFileName: {
      description: '사용 가능한 {{tokens}}을 참조하세요.\n현재 첨부 파일 이름을 유지하려면 비워두세요.',
      name: '수집된 첨부 파일 이름'
    },
    customTokens: {
      description: '사용할 사용자 정의 토큰입니다.\n자세한 내용은 {{documentation}}를 참조하세요.\n⚠️ 사용자 정의 토큰은 임의의 JavaScript 코드일 수 있습니다. 잘못 작성되면 데이터 손실을 일으킬 수 있습니다. 본인 책임하에 사용하세요.',
      name: '사용자 정의 토큰'
    },
    defaultImageSize: {
      description: '기본 이미지 크기입니다.\n픽셀({{pixels}}) 또는 전체 이미지 크기에 대한 백분율({{percentage}})로 지정할 수 있습니다.\n원본 이미지 크기를 사용하려면 비워두세요.',
      name: '기본 이미지 크기'
    },
    duplicateNameSeparator: {
      description: '기존 파일과 같은 이름의 파일을 붙여넣거나 드래그하면 이 구분자가 파일 이름에 추가됩니다.\n예를 들어 {{existingFile}} 파일을 드래그하면 {{firstAvailableName}}, {{secondAvailableName}} 등 사용 가능한 첫 번째 이름으로 변경됩니다.',
      name: '중복 이름 구분자'
    },
    excludePathsFromAttachmentCollecting: {
      description: '{{command}} 명령을 실행할 때 다음 경로의 첨부 파일을 제외합니다.\n각 경로를 새 줄에 입력하세요.\n{{pathSyntax}}\n설정이 비어 있으면 첨부 파일 수집에서 제외되는 경로가 없습니다.',
      name: '첨부 파일 수집에서 제외할 경로'
    },
    generatedAttachmentFileName: {
      description: '사용 가능한 {{tokens}}을 참조하세요.',
      name: '생성된 첨부 파일 이름'
    },
    jpegQuality: {
      description: '품질이 낮을수록 압축률이 높아집니다.',
      name: 'JPEG 품질'
    },
    locationForNewAttachments: {
      description: '노트의 상위 폴더를 기준으로 한 상대 경로를 사용하려면 {{relativePrefix}}(으)로 시작하세요.\n사용 가능한 {{tokens}}을 참조하세요.\n{{dotFolder}} 같은 점 폴더는 Obsidian이 추적하지 않으므로 권장되지 않습니다. 관리하려면 {{unhidePlugin}} 플러그인이 필요할 수 있습니다.',
      name: '새 첨부 파일 위치'
    },
    markdownUrlFormat: {
      description: '첨부 파일을 추가할 때 Markdown에 삽입될 URL의 형식입니다. 이 형식은 그 시점에만 적용됩니다. 나중에 노트나 첨부 파일의 이름이 변경되거나 이동되어 Obsidian이 다시 쓰는 링크는 기본 형식을 따릅니다.\n사용 가능한 {{tokens}}을 참조하세요.\n기본 형식을 사용하려면 비워두세요.',
      name: 'Markdown URL 형식'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: '다른 플러그인이 만든 첨부 파일에도 첨부 폴더 및 파일 이름 설정을 적용할지 여부입니다.\n일부 플러그인은 첨부 파일이 어디에 속하는지 Obsidian에 묻지 않고 자체 이름으로 보관함에 씁니다. 이 옵션을 켜면 그런 파일은 나타나는 즉시 이동되고 이름이 변경됩니다.\n노트가 열려 있는 동안 만들어지고 노트에서 링크된 파일만 처리됩니다. 어떤 노트에서도 링크되지 않은 파일은 다른 플러그인이 자체적으로 보관하는 데이터이므로 기록된 위치에 그대로 둡니다. 동기화나 보관함 가져오기로 들어온 파일은 절대 건드리지 않습니다.\n{{modes}}\n파일을 만든 플러그인은 쓰기 작업의 호출 스택으로 식별합니다. 이는 최선의 노력에 따른 것입니다. Obsidian 자체, 동기화 클라이언트 또는 쓰기를 지연하는 플러그인이 기록한 파일은 플러그인이 식별되지 않습니다. 그런 파일은 아래 목록에 없는 것으로 간주됩니다.',
      name: '다른 플러그인이 만든 첨부 파일 이름 변경'
    },
    renameAttachmentsToLowerCase: '첨부 파일을 소문자로 이름 변경',
    renamedAttachmentFileName: {
      description: '사용 가능한 {{tokens}}을 참조하세요.\n현재 첨부 파일 이름을 유지하려면 비워두세요.',
      name: '이름이 변경된 첨부 파일 이름'
    },
    resetToSampleCustomTokens: {
      message: '사용자 정의 토큰을 샘플 사용자 정의 토큰으로 재설정하시겠습니까? 변경사항이 손실됩니다.',
      title: '샘플 사용자 정의 토큰으로 재설정'
    },
    shouldConvertPastedImagesToJpeg: {
      description: '붙여넣은 이미지를 JPEG로 변환할지 여부입니다. PNG 이미지 내용이 클립보드에서 직접 붙여넣어질 때만 적용됩니다. 일반적으로 스크린샷 붙여넣기에 사용됩니다.',
      name: '붙여넣은 이미지를 JPEG로 변환'
    },
    shouldRenameCollectedAttachments: {
      description: '활성화하면 {{command}} 명령으로 처리된 첨부 파일의 이름이 {{setting}} 설정에 따라 변경됩니다.',
      name: '수집된 첨부 파일 이름 변경'
    },
    specialCharacters: {
      description: '첨부 파일 폴더 및 파일 이름에서 교체하거나 제거할 특수 문자입니다.\n특수 문자를 보존하려면 비워두세요.',
      name: '특수 문자'
    },
    specialCharactersReplacement: {
      description: '첨부 파일 폴더 및 파일 이름의 특수 문자에 대한 교체 문자열입니다.\n특수 문자를 제거하려면 비워두세요.',
      name: '특수 문자 교체'
    },
    timeoutInSeconds: {
      description: '모든 작업에 대한 타임아웃(초)입니다.\n{{zero}}(으)로 설정하면 작업 실행 타임아웃이 비활성화됩니다.',
      name: '시간 초과(초)'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: '첨부 파일 이름 변경',
    folderTitle: '첨부 폴더 선택',
    previewModal: {
      title: '첨부 파일 미리보기 \'{{fullFileName}}\''
    },
    title: '프롬프트 토큰에 대한 값을 제공하세요'
  },
  regularExpression: '/정규식/'
};
