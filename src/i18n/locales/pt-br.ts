export const ptBR = {
  attachmentCollector: {
    confirm: 'Você deseja coletar anexos para todas as notas nas pastas de forma recursiva?\n{{folders}}\nEsta operação não pode ser desfeita.',
    progressBar: {
      message: 'Coletando anexos {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Coletando anexos...'
    }
  },
  buttons: {
    copy: 'Copiar',
    move: 'Mover',
    previewAttachmentFile: 'Visualizar arquivo anexo',
    skip: 'Pular'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'O anexo {{attachment}} é referenciado por múltiplas notas.',
    heading: 'Coletando anexo usado por múltiplas notas',
    noPriorityWinnerReason: {
      EmptyList: 'Não foi movido porque a configuração {{settingName}} está vazia, então nada decide qual destas notas o possui.',
      NoMatch: 'Não foi movido porque nenhuma destas notas corresponde a qualquer entrada da configuração {{settingName}}.',
      Tie: 'Não foi movido porque várias destas notas correspondem igualmente bem à configuração {{settingName}}, então ela não indica um único proprietário.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Usar a mesma ação para outros anexos problemáticos'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Coletar anexos na pasta atual',
    collectAttachmentsCurrentNote: 'Coletar anexos na nota atual',
    collectAttachmentsEntireVault: 'Coletar anexos em todo o cofre'
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
    collectingAttachments: 'Coletando anexos para \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Coleta de anexos cancelada. Veja o console para detalhes.',
    generatedAttachmentFileNameIsInvalid: 'O nome de arquivo de anexo gerado \'{{path}}\' é inválido.\n{{validationMessage}}\nVerifique a configuração {{settingName}}.',
    notePathIsIgnored: 'Caminho da nota foi ignorado'
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
      attachmentIsStillUsed: 'Anexo {{attachmentPath}} ainda está sendo usado por outras notas. Não será excluído.',
      unhandledError: 'Ocorreu um erro não tratado. Por favor, verifique o console para mais informações.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'todos os arquivos são renomeados.',
        displayText: 'Todos'
      },
      none: {
        description: 'seus nomes são preservados.',
        displayText: 'Nenhum'
      },
      onlyPastedImages: {
        description: 'apenas imagens coladas são renomeadas. Aplica-se apenas quando o conteúdo da imagem PNG é colado da área de transferência diretamente. Tipicamente, para colar capturas de tela.',
        displayText: 'Apenas imagens coladas'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'cancelar a coleta de anexos.',
        displayText: 'Cancelar'
      },
      copy: {
        description: 'copiar o anexo para o novo local.',
        displayText: 'Copiar'
      },
      move: {
        description: 'mover o anexo para o novo local.',
        displayText: 'Mover'
      },
      prompt: {
        description: 'solicitar ao usuário que escolha a ação.',
        displayText: 'Solicitar'
      },
      skip: {
        description: 'pular o anexo e prosseguir para o próximo.',
        displayText: 'Pular'
      }
    },
    defaultImageSizeDimension: {
      height: 'Altura',
      width: 'Largura'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Tokens personalizados foram comentados pois precisam ser atualizados para o novo formato introduzido na versão 9.0.0 do plugin.\n// Consulte a documentação ({{customTokensDocumentationUrl}}) para mais informações.',
      deprecated: 'O formato de registro de tokens personalizados mudou. Por favor, atualize seus tokens adequadamente. Consulte a {{documentation}} para mais informações.'
    },
    legacyRenameAttachmentsToLowerCase: 'A configuração {{setting}} está obsoleta. Use o formato {{format}} em vez disso. Veja a {{documentation}} para mais informações.',
    markdownUrlFormat: {
      deprecated: 'Você tem um valor potencialmente incorreto definido para o formato {{setting}}. Por favor, consulte a {{documentation}} para mais informações. Esta mensagem não será exibida novamente.'
    },
    specialCharacters: 'O valor padrão da configuração {{setting}} foi alterado. Seu valor de configuração foi atualizado para o novo valor padrão.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'O tamanho padrão da imagem deve estar em pixels ou porcentagem',
      invalidCustomTokensCode: 'Código de tokens personalizados inválido',
      invalidRegularExpression: 'Expressão regular inválida {{regExp}}',
      specialCharactersMustNotContainSlash: 'Caracteres especiais não devem conter /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'A substituição de caracteres especiais não deve conter caracteres de caminho de nome de arquivo inválidos.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Ao anexar arquivos:',
      name: 'Modo de renomeação de anexos'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Quando o anexo coletado é usado por múltiplas notas:',
      name: 'Modo de coleta de anexos usados por múltiplas notas'
    },
    collectedAttachmentFileName: {
      description: 'Veja os {{tokens}} disponíveis.\nDeixe em branco para manter o nome atual do arquivo de anexo.',
      name: 'Nome do arquivo de anexo coletado'
    },
    customTokens: {
      description: 'Tokens personalizados a serem usados.\nVeja a {{documentation}} para mais informações.\n⚠️ Tokens personalizados podem ser código JavaScript arbitrário. Se mal escritos, podem causar perda de dados. Use por sua própria conta e risco.',
      name: 'Tokens personalizados'
    },
    defaultImageSize: {
      description: 'O tamanho padrão da imagem.\nPode ser especificado em pixels ({{pixels}}) ou como porcentagem do tamanho total da imagem ({{percentage}}).\nDeixe em branco para usar o tamanho original da imagem.',
      name: 'Tamanho padrão da imagem'
    },
    duplicateNameSeparator: {
      description: 'Ao colar/arrastar um arquivo com o mesmo nome de um arquivo existente, este separador será adicionado ao nome do arquivo.\nPor exemplo, ao arrastar o arquivo {{existingFile}}, ele será renomeado para {{firstAvailableName}}, {{secondAvailableName}} etc., recebendo o primeiro nome disponível.',
      name: 'Separador de nome duplicado'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Excluir anexos dos seguintes caminhos quando o comando {{command}} for executado.\nInsira cada caminho em uma nova linha.\n{{pathSyntax}}\nSe a configuração estiver vazia, nenhum caminho será excluído da coleta de anexos.',
      name: 'Excluir caminhos da coleta de anexos'
    },
    generatedAttachmentFileName: {
      description: 'Veja os {{tokens}} disponíveis.',
      name: 'Nome do arquivo de anexo gerado'
    },
    jpegQuality: {
      description: 'Quanto menor a qualidade, maior a taxa de compressão.',
      name: 'Qualidade JPEG'
    },
    locationForNewAttachments: {
      description: 'Comece com {{relativePrefix}} para caminhos relativos à pasta pai da nota.\nVeja os {{tokens}} disponíveis.\nPastas que começam com ponto, como {{dotFolder}}, não são recomendadas, pois o Obsidian não as rastreia. Você pode precisar usar o plugin {{unhidePlugin}} para gerenciá-las.',
      name: 'Localização para novos anexos'
    },
    markdownUrlFormat: {
      description: 'Formato da URL que será inserida no Markdown quando um anexo for adicionado. Ele é aplicado somente nesse momento: um link que o Obsidian reescrever depois, quando uma nota ou um anexo for renomeado ou movido, recebe o formato padrão.\nVeja os {{tokens}} disponíveis.\nDeixe em branco para usar o formato padrão.',
      name: 'Formato de URL no Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Se as configurações de pasta de anexos e de nome de arquivo devem ser aplicadas a anexos criados por OUTROS plugins.\nAlguns plugins gravam um anexo no cofre com um nome próprio, sem perguntar ao Obsidian onde ele deve ficar. Com esta opção ativada, esse arquivo é movido e renomeado assim que aparece.\nSomente arquivos criados enquanto uma nota está aberta, e vinculados a partir de uma nota, são tocados: um arquivo ao qual nenhuma nota faz link contém dados que outro plugin guarda para si e permanece onde foi gravado. Arquivos que chegam de uma sincronização ou de uma importação de cofre nunca são tocados.\n{{modes}}\nO plugin criador é identificado pela pilha de chamadas da gravação. Isso é feito na base do melhor esforço: nenhum plugin é identificado para um arquivo gravado pelo próprio Obsidian, por um cliente de sincronização ou por um plugin que adia sua gravação. Esse arquivo conta como NÃO estando na lista abaixo.',
      name: 'Renomear anexos criados por outros plugins'
    },
    renameAttachmentsToLowerCase: 'Renomear anexos para letras minúsculas',
    renamedAttachmentFileName: {
      description: 'Veja os {{tokens}} disponíveis.\nDeixe em branco para manter o nome atual do arquivo de anexo.',
      name: 'Nome do arquivo de anexo renomeado'
    },
    resetToSampleCustomTokens: {
      message: 'Tem certeza de que deseja redefinir os tokens personalizados para os tokens de exemplo? Suas alterações serão perdidas.',
      title: 'Redefinir para tokens de exemplo'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Se deve converter imagens coladas em JPEG. Aplica-se apenas quando o conteúdo da imagem PNG é colado diretamente da área de transferência. Tipicamente, para capturas de tela.',
      name: 'Converter imagens coladas para JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Se ativado, os anexos processados pelos comandos {{command}} serão renomeados de acordo com a configuração {{setting}}.',
      name: 'Renomear anexos coletados'
    },
    specialCharacters: {
      description: 'Caracteres especiais no nome da pasta e do arquivo de anexos a serem substituídos ou removidos.\nDeixe em branco para preservar os caracteres especiais.',
      name: 'Caracteres especiais'
    },
    specialCharactersReplacement: {
      description: 'String de substituição para caracteres especiais no nome da pasta e do arquivo de anexos.\nDeixe em branco para remover os caracteres especiais.',
      name: 'Substituição de caracteres especiais'
    },
    timeoutInSeconds: {
      description: 'O tempo limite em segundos para todas as operações.\nSe {{zero}} estiver definido, o tempo limite de execução das operações será desativado.',
      name: 'Tempo limite em segundos'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Renomear arquivo anexo',
    folderTitle: 'Escolher pasta de anexos',
    previewModal: {
      title: 'Visualizar arquivo anexo \'{{fullFileName}}\''
    },
    title: 'Forneça um valor para o token de prompt'
  },
  regularExpression: '/expressão regular/'
};
