export const pt = {
  attachmentCollector: {
    confirm: 'Pretende recolher os anexos de todas as notas nas pastas, de forma recursiva?\n{{folders}}\nEsta operação não pode ser desfeita.',
    progressBar: {
      message: 'Recolhendo anexos {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Recolhendo anexos...'
    }
  },
  buttons: {
    copy: 'Copiar',
    move: 'Mover',
    previewAttachmentFile: 'Pré-visualizar ficheiro anexo',
    skip: 'Saltar'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'O anexo {{attachment}} é referenciado por múltiplas notas.',
    heading: 'Recolhendo anexo usado por múltiplas notas',
    noPriorityWinnerReason: {
      EmptyList: 'Não foi movido porque a definição {{settingName}} está vazia, pelo que nada decide qual destas notas o possui.',
      NoMatch: 'Não foi movido porque nenhuma destas notas corresponde a qualquer entrada da definição {{settingName}}.',
      Tie: 'Não foi movido porque várias destas notas correspondem igualmente bem à definição {{settingName}}, pelo que esta não indica um único proprietário.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Usar a mesma ação para outros anexos problemáticos'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Recolher anexos na pasta atual',
    collectAttachmentsCurrentNote: 'Recolher anexos na nota atual',
    collectAttachmentsEntireVault: 'Recolher anexos em todo o cofre'
  },
  links: {
    documentation: 'documentação',
    tokens: 'tokens'
  },
  menuItems: {
    collectAttachmentsInFile: 'Coletar anexos no arquivo',
    collectAttachmentsInFiles: 'Coletar anexos nos arquivos'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Recolhendo anexos para \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Recolha de anexos cancelada. Veja a consola para detalhes.',
    generatedAttachmentFileNameIsInvalid: 'O nome de ficheiro de anexo gerado \'{{path}}\' é inválido.\n{{validationMessage}}\nVerifique a configuração {{settingName}}.',
    notePathIsIgnored: 'Caminho da nota é ignorado'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Cancelar',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Itens por página:',
      jumpToPage: 'Ir para página:'
    },
    notices: {
      attachmentIsStillUsed: 'O anexo {{attachmentPath}} ainda está a ser usado por outras notas. Não será eliminado.',
      unhandledError: 'Ocorreu um erro não tratado. Verifique a consola para mais informações.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'todos os ficheiros são renomeados.',
        displayText: 'Todos'
      },
      none: {
        description: 'os seus nomes são preservados.',
        displayText: 'Nenhum'
      },
      onlyPastedImages: {
        description: 'apenas imagens coladas são renomeadas. Aplica-se apenas quando o conteúdo da imagem PNG é colado diretamente da área de transferência. Tipicamente, para colar capturas de ecrã.',
        displayText: 'Apenas imagens coladas'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'cancelar a recolha de anexos.',
        displayText: 'Cancelar'
      },
      copy: {
        description: 'copiar o anexo para a nova localização.',
        displayText: 'Copiar'
      },
      move: {
        description: 'mover o anexo para a nova localização.',
        displayText: 'Mover'
      },
      prompt: {
        description: 'solicitar ao utilizador que escolha a ação.',
        displayText: 'Solicitar'
      },
      skip: {
        description: 'saltar o anexo e prosseguir para o seguinte.',
        displayText: 'Saltar'
      }
    },
    defaultImageSizeDimension: {
      height: 'Altura',
      width: 'Largura'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Os tokens personalizados foram comentados pois necessitam de ser atualizados para o novo formato introduzido na versão 9.0.0 do plugin.\n// Consulte a documentação ({{customTokensDocumentationUrl}}) para mais informações.',
      deprecated: 'O formato de registo de tokens personalizados mudou. Por favor, atualize os seus tokens em conformidade. Consulte a {{documentation}} para mais informações.'
    },
    legacyRenameAttachmentsToLowerCase: 'A configuração {{setting}} está obsoleta. Use antes o formato {{format}}. Consulte a {{documentation}} para mais informações.',
    markdownUrlFormat: {
      deprecated: 'Tem um valor potencialmente incorreto definido para o formato {{setting}}. Consulte a {{documentation}} para mais informações. Esta mensagem não será exibida novamente.'
    },
    specialCharacters: 'O valor padrão da configuração {{setting}} foi alterado. O seu valor foi atualizado para o novo padrão.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'O tamanho predefinido da imagem deve estar em pixels ou percentagem',
      invalidCustomTokensCode: 'Código de tokens personalizados inválido',
      invalidRegularExpression: 'Expressão regular inválida {{regExp}}',
      specialCharactersMustNotContainSlash: 'Caracteres especiais não devem conter /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'A substituição de caracteres especiais não deve conter caracteres inválidos de caminho de nome de ficheiro.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Ao anexar ficheiros:',
      name: 'Modo de renomeação de anexos'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Quando o anexo recolhido é usado por múltiplas notas:',
      name: 'Modo de recolha de anexos usados por múltiplas notas'
    },
    collectedAttachmentFileName: {
      description: 'Veja os {{tokens}} disponíveis.\nDeixe em branco para manter o nome atual do ficheiro de anexo.',
      name: 'Nome do ficheiro de anexo recolhido'
    },
    customTokens: {
      description: 'Tokens personalizados a serem usados.\nConsulte a {{documentation}} para mais informações.\n⚠️ Tokens personalizados podem conter código JavaScript arbitrário. Se mal escritos, podem causar perda de dados. Use por sua conta e risco.',
      name: 'Tokens personalizados'
    },
    defaultImageSize: {
      description: 'O tamanho predefinido da imagem.\nPode ser especificado em pixels ({{pixels}}) ou como percentagem do tamanho total da imagem ({{percentage}}).\nDeixe em branco para usar o tamanho original da imagem.',
      name: 'Tamanho predefinido da imagem'
    },
    duplicateNameSeparator: {
      description: 'Ao colar/arrastar um ficheiro com o mesmo nome de um ficheiro existente, este separador será adicionado ao nome do ficheiro.\nPor exemplo, ao arrastar o ficheiro {{existingFile}}, este será renomeado para {{firstAvailableName}}, {{secondAvailableName}}, etc., recebendo o primeiro nome disponível.',
      name: 'Separador de nomes duplicados'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Excluir anexos dos seguintes caminhos quando o comando {{command}} for executado.\nIntroduza cada caminho numa nova linha.\n{{pathSyntax}}\nSe a configuração ficar vazia, nenhum caminho será excluído da recolha de anexos.',
      name: 'Excluir caminhos da recolha de anexos'
    },
    generatedAttachmentFileName: {
      description: 'Veja os {{tokens}} disponíveis.',
      name: 'Nome do ficheiro de anexo gerado'
    },
    jpegQuality: {
      description: 'Quanto menor a qualidade, maior a taxa de compressão.',
      name: 'Qualidade JPEG'
    },
    locationForNewAttachments: {
      description: 'Comece com {{relativePrefix}} para caminhos relativos à pasta-mãe da nota.\nVeja os {{tokens}} disponíveis.\nPastas começadas por ponto, como {{dotFolder}}, não são recomendadas, pois o Obsidian não as acompanha. Poderá necessitar do plugin {{unhidePlugin}} para as gerir.',
      name: 'Localização para novos anexos'
    },
    markdownUrlFormat: {
      description: 'Formato do URL a inserir no Markdown quando é adicionado um anexo. É aplicado apenas nesse momento: uma ligação que o Obsidian reescreva mais tarde, quando uma nota ou um anexo é renomeado ou movido, recebe o formato padrão.\nVeja os {{tokens}} disponíveis.\nDeixe em branco para usar o formato padrão.',
      name: 'Formato de URL em Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Se as definições de pasta de anexos e de nome de ficheiro devem ser aplicadas a anexos criados por OUTROS plugins.\nAlguns plugins escrevem um anexo no cofre com um nome próprio, sem perguntar ao Obsidian onde deve ficar. Com esta opção ativada, esse ficheiro é movido e renomeado assim que aparece.\nSó são tocados os ficheiros criados com uma nota aberta e ligados a partir de uma nota: um ficheiro para o qual nenhuma nota tem ligação contém dados que outro plugin guarda para si e fica onde foi escrito. Os ficheiros que chegam de uma sincronização ou de uma importação de cofre nunca são tocados.\n{{modes}}\nO plugin que criou o ficheiro é identificado pela pilha de chamadas da escrita. Isto é feito na medida do possível: não é identificado nenhum plugin para um ficheiro escrito pelo próprio Obsidian, por um cliente de sincronização ou por um plugin que adia a sua escrita. Esse ficheiro conta como NÃO estando na lista abaixo.',
      name: 'Renomear anexos criados por outros plugins'
    },
    renameAttachmentsToLowerCase: 'Renomear anexos para minúsculas',
    renamedAttachmentFileName: {
      description: 'Veja os {{tokens}} disponíveis.\nDeixe em branco para manter o nome atual do ficheiro de anexo.',
      name: 'Nome do ficheiro de anexo renomeado'
    },
    resetToSampleCustomTokens: {
      message: 'Tem a certeza de que deseja repor os tokens personalizados para os tokens de exemplo? As suas alterações serão perdidas.',
      title: 'Repor tokens personalizados para o exemplo'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Defina se as imagens coladas devem ser convertidas para JPEG. Aplica-se apenas quando o conteúdo da imagem PNG é colado diretamente da área de transferência. Tipicamente, útil para capturas de ecrã.',
      name: 'Converter imagens coladas para JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Se ativado, os anexos processados através dos comandos {{command}} serão renomeados de acordo com a configuração {{setting}}.',
      name: 'Renomear anexos recolhidos'
    },
    specialCharacters: {
      description: 'Caracteres especiais no nome da pasta e do ficheiro de anexo a serem substituídos ou removidos.\nDeixe em branco para preservar os caracteres especiais.',
      name: 'Caracteres especiais'
    },
    specialCharactersReplacement: {
      description: 'Sequência de substituição para caracteres especiais no nome da pasta e do ficheiro de anexo.\nDeixe em branco para remover os caracteres especiais.',
      name: 'Substituição de caracteres especiais'
    },
    timeoutInSeconds: {
      description: 'O tempo limite em segundos para todas as operações.\nSe {{zero}} estiver definido, o tempo limite de execução das operações é desativado.',
      name: 'Tempo limite em segundos'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Renomear ficheiro anexo',
    folderTitle: 'Escolher pasta de anexos',
    previewModal: {
      title: 'Pré-visualizar ficheiro anexo \'{{fullFileName}}\''
    },
    title: 'Forneça um valor para o token de prompt'
  },
  regularExpression: '/expressão regular/'
};
